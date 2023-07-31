// @file circuit.cpp -- encrypted circuit evaluation object
//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other
// contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//==================================================================================
#include "circuit.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>

#include "utils.h"
#include <boost/range/adaptor/reversed.hpp>

Circuit::Circuit(lbcrypto::BINFHE_PARAMSET set,
                 lbcrypto::BINFHE_METHOD method) {
  // clear all flags
  this->plaintext_flag = false; // if true perform plaintext logic
  this->encrypted_flag = false; // if true perform encrypted logic
  this->verify_flag = false;    // if true verify plaintext vs encrypted logic

  this->done = false;
  // create empty containers
  this->nl = NetList(); // full net list of the ckt (all wires and fanout
                        // gates)

  this->waitingWireNames = WireNameList(0);
  this->activeWires = WireQueue(0);

  this->inputGates = GateList(0); // input gates in ckt
  this->allGates = GateList(0);   // all other gates in ckt

  this->readyGates = GateQueue(0);
  this->waitingGates = GateQueue(0);
  this->executingGates = GateQueue(0);
  this->doneGates = GateQueue(0);
  std::cout << "Generating crypto context" << std::endl;
  this->cc = lbcrypto::BinFHEContext();
  if (set == lbcrypto::TOY) {
    std::cout << "*************************" << std::endl;
    std::cout << "WARNING TOY Security used" << std::endl;
    std::cout << "*************************" << std::endl;
  } else if (set == lbcrypto::STD128) {
    std::cout << "STD 128 Optimized Security used" << std::endl;
  } else {
    std::cerr << "Error Bad security" << std::endl;
    exit(-1);
  }
  if (method == lbcrypto::AP) {
    std::cout << "AP used" << std::endl;
  } else if (method == lbcrypto::GINX) {
    std::cout << "GINX used" << std::endl;
  } else {
    std::cerr << "Error Bad method" << std::endl;
    exit(-1);
  }

  this->cc.GenerateBinFHEContext(set, method);
  std::cout << "Generating crypto keys" << std::endl;
  this->sk = cc.KeyGen();
  this->cc.BTKeyGen(this->sk);
  std::cout << "Done" << std::endl;
  this->gep.cc = this->cc;
  this->gep.sk = this->sk;
  this->gep.plaintext_flag = this->plaintext_flag;
  this->gep.encrypted_flag = this->encrypted_flag;
  this->gep.verify_flag = this->verify_flag;
}

Circuit::~Circuit(void) {}

bool Circuit::ReadFile(std::string inFname) {
  // parse the input file and generate the
  // various lists to define the circuit.

  // std::vector <unsigned int> out(n_out_bits, 0);
  // //Plaintext out
  // std::vector <unsigned int> pout(n_out_bits, 0);
  std::cout << "Loading circuit description " << inFname << std::endl;

  // open the program file to determine some parameters for tests
  std::ifstream inFile;
  // Set exceptions to be thrown on failure
  inFile.exceptions(std::ifstream::failbit | std::ifstream::badbit);

  try {
    inFile.open(inFname.c_str());
  } catch (std::system_error &e) {
    std::cerr << e.code().message() << std::endl;
    std::cerr << "error opening file.. exiting!" << std::endl;
    exit(-1);
  }

  unsigned int lineNo = 0;
  unsigned int gateNo = 0;

  unsigned int max_output_bits(0);
  std::string tline;
  try {
    while (std::getline(inFile, tline)) {
      lineNo++;
      if (lineNo % 100 == 0) {
        std::cout << "\r loading line " << lineNo << std::flush;
      }
      if (tline[0] == '#') {
        continue; // ignore comment lines
      }
      Gate g;
      g.plainin.resize(2);
      g.encin.resize(2);

      unsigned int n1, n2, n3;
      unsigned int n;
      if (contains(tline, "LOAD")) {
        n = sscanf(tline.c_str(), "R%d = LOAD(In%d, %d)", &n1, &n2, &n3);
        if (n != 3) {
          std::cerr << "LOAD parse error line " << lineNo << std::endl;
          exit(-1);
        }

        // create INPUT gate
        // load input n2, bit n3 to register n1
        // reg[n1] = in[n2-1][n3];
        g.name = "INPUT:" + std::to_string(gateNo);
        g.op = GateEnum::INPUT;
        std::string in1, in2, out1;
        in1 = "IN:" + std::to_string(n2 - 1);
        in2 = "BIT:" + std::to_string(n3);
        out1 = "R:" + std::to_string(n1);
        g.inWireNames.push_back(in1);
        g.inWireNames.push_back(in2);
        g.ready.push_back(false);
        g.ready.push_back(false);
        g.outWireNames.push_back(out1);
        g.plainin.resize(1); // adjust to only one input
        g.encin.resize(1);

        gateNo++;
        this->inputGates.push_back(g);

      } else if (contains(tline, "STORE")) {
        n = sscanf(tline.c_str(), "Out%d = STORE(R%d)", &n1, &n2);
        if (n != 2) {
          std::cerr << "STORE parse error line " << lineNo << std::endl;
          exit(-1);
        }
        // store register n2 into out n1
        // out[n1] = reg[n2];
        g.name = "OUTPUT:" + std::to_string(gateNo);
        g.op = GateEnum::OUTPUT;
        std::string in1, out1, out2;
        in1 = "R:" + std::to_string(n2);
        // right now there is only one output allowed
        out1 = "OUT:" + std::to_string(0);
        out2 = "BIT:" + std::to_string(n1);
        g.inWireNames.push_back(in1);
        g.ready.push_back(false);
        g.outWireNames.push_back(out1);
        g.outWireNames.push_back(out2);
        g.plainin.resize(1); // adjust to only one input
        g.encin.resize(1);

        gateNo++;
        this->allGates.push_back(g);

        // update the output bit size
        max_output_bits = std::max(max_output_bits, n1);

      } else if (contains(tline, "NOT")) {
        n = sscanf(tline.c_str(), "R%d = NOT(R%d)", &n1, &n2);
        if (n != 2) {
          std::cerr << "NOT parse error line " << lineNo << std::endl;
          exit(-1);
        }

        //  register n1 = not(register n2)
        // store register n2 into out n1
        // out[n1] = reg[n2];
        g.name = "NOT:" + std::to_string(gateNo);
        g.op = GateEnum::NOT;
        std::string in1, out1;
        in1 = "R:" + std::to_string(n2);
        out1 = "R:" + std::to_string(n1);
        g.inWireNames.push_back(in1);
        g.ready.push_back(false);
        g.outWireNames.push_back(out1);
        g.plainin.resize(1); // adjust to only one input
        g.encin.resize(1);

        gateNo++;
        this->allGates.push_back(g);

      } else if (contains(tline, "AND")) {
        n = sscanf(tline.c_str(), "R%d = AND(R%d, R%d)", &n1, &n2, &n3);
        if (n != 3) {
          std::cerr << "AND parse error line " << lineNo << std::endl;
          exit(-1);
        }

        //  register n1 = and(n2, n3)
        // reg[n1] = and(reg[n2], reg[n3]);
        g.name = "AND:" + std::to_string(gateNo);
        g.op = GateEnum::AND;
        std::string in1, in2, out1;
        in1 = "R:" + std::to_string(n2);
        in2 = "R:" + std::to_string(n3);
        out1 = "R:" + std::to_string(n1);
        g.inWireNames.push_back(in1);
        g.inWireNames.push_back(in2);
        g.ready.push_back(false);
        g.ready.push_back(false);
        g.outWireNames.push_back(out1);
        gateNo++;
        this->allGates.push_back(g);

      } else if (contains(tline, " OR")) {
        n = sscanf(tline.c_str(), "R%d = OR(R%d, R%d)", &n1, &n2, &n3);
        if (n != 3) {
          std::cerr << "OR parse error line " << lineNo << std::endl;
          exit(-1);
        }

        //  register n1 = or(n2, n3)
        // reg[n1] = or(reg[n2], reg[n3]);
        // reg[n1] = reg[n2] or reg[n3];
        g.name = "OR:" + std::to_string(gateNo);
        g.op = GateEnum::OR;
        std::string in1, in2, out1;
        in1 = "R:" + std::to_string(n2);
        in2 = "R:" + std::to_string(n3);
        out1 = "R:" + std::to_string(n1);
        g.inWireNames.push_back(in1);
        g.inWireNames.push_back(in2);
        g.ready.push_back(false);
        g.ready.push_back(false);
        g.outWireNames.push_back(out1);
        gateNo++;
        this->allGates.push_back(g);

      } else if (contains(tline, "XOR")) {
        n = sscanf(tline.c_str(), "R%d = XOR(R%d, R%d)", &n1, &n2, &n3);
        if (n != 3) {
          std::cerr << "XOR parse error line " << lineNo << std::endl;
          exit(-1);
        }
        //  register n1 = xor(n2, n3)
        // reg[n1] = xor(reg[n2], reg[n3]);
        g.name = "XOR:" + std::to_string(gateNo);
        g.op = GateEnum::XOR;
        std::string in1, in2, out1;
        in1 = "R:" + std::to_string(n2);
        in2 = "R:" + std::to_string(n3);
        out1 = "R:" + std::to_string(n1);
        g.inWireNames.push_back(in1);
        g.inWireNames.push_back(in2);
        g.ready.push_back(false);
        g.ready.push_back(false);
        g.outWireNames.push_back(out1);
        gateNo++;
        this->allGates.push_back(g);

      } else if (contains(tline, "BOOT")) {
        // No op
      }

    } // while
  } catch (std::system_error &e) {
    // std::cout<<"end of file"<<std::endl;
    // end of file here.
  }
  try {
    inFile.close();
  } catch (std::system_error &e) {
    std::cerr << e.code().message() << std::endl;
    exit(-1);
  }

  // save output space
  // for now fixed to single output bus.
  max_output_bits++; // count was from 0
  std::cout << std::endl
            << "generating output nbits " << max_output_bits << std::endl;

  this->n_outputs = 1; // fixed for now
  this->n_output_bits.resize(1);
  this->n_output_bits[0] = max_output_bits;
  this->circuitOut.resize(1);
  this->circuitOut[0].resize(max_output_bits);
  std::cout << "circuit out size " << this->circuitOut.size() << std::endl;
  std::cout << "circuit[0] out size " << this->circuitOut[0].size()
            << std::endl;

  // generate netlist
  std::cout << "generating netlist" << std::endl;
  // start with input gates
  for (auto og : this->inputGates) { // for all input gates

    for (auto ow : og.outWireNames) { // for each output
      GateNameList fanout(0);
      fanout.reserve(16);                // arbitrary
      for (auto ig : this->allGates) {   // loop through all gates
        for (auto iw : ig.inWireNames) { // for all input wires.
          if (ow == iw) {
            fanout.push_back(ig.name);
          }
        }
      }
      nl.insert({ow, fanout});
    }
  }
  // repeat for the remaining gates
  for (auto og : this->allGates) {    // for all input gates
    for (auto ow : og.outWireNames) { // for each output
      GateNameList fanout(0);
      for (auto ig : this->allGates) {   // loop through all gates
        for (auto iw : ig.inWireNames) { // for all input wires.
          if (ow == iw) {
            fanout.push_back(ig.name);
          }
        }
      }
      nl.insert({ow, fanout});
    }
  }

  // clear all other queues
  waitingWireNames.clear();
  activeWires.clear();

  waitingGates.clear();
  readyGates.clear();
  executingGates.clear();
  doneGates.clear();
  std::cout << "Done" << std::endl;
  return true;
}

void Circuit::Reset(void) {
  OPENFHE_DEBUG_FLAG(false);

  // clear counters
  this->n_input_gates = 0;
  this->n_output_gates = 0;
  this->n_and_gates = 0;
  this->n_or_gates = 0;
  this->n_xor_gates = 0;
  this->n_not_gates = 0;

  // clear all flags
  this->plaintext_flag = false;
  this->encrypted_flag = false;
  this->verify_flag = false;

  this->done = false;

  // clear all queues and lists
  waitingWireNames.clear();
  activeWires.clear();

  waitingGates.clear();
  readyGates.clear();
  executingGates.clear();
  examinedGates.clear();
  doneGates.clear();

  // load all gates (except input) to waitingGate queue from allGates;
  for (auto g : this->allGates) {
    waitingGates.push_back(g);
  }

  // reserve capacity for all other gateQueues
  // auto maxGates = waitingGates.size();
  // readyGates.reserve(maxGates);
  readyGates.clear(); // capacity should be unchanged
  // executingGates.reserve(maxGates);
  executingGates.clear();
  // examinedGates.reserve(maxGates);
  examinedGates.clear();
  // doneGates.reserve(maxGates);
  doneGates.clear();

  OPENFHE_DEBUG("reset: before waiting gates size: " << waitingGates.size());
  // load all wirenames to waitingWire queue from netlist
  for (auto const &w : this->nl) {
    waitingWireNames.push_back(w.first);
  }
  OPENFHE_DEBUG(
      "reset: now waiting wirename size: " << waitingWireNames.size());
}

bool Circuit::_parse_input(Inputs input, std::string input_name,
                           std::string bit_name) {
  // input_name is IN:#  bit_name is BIT:#

  std::stringstream s1(input_name);
  std::string token;
  getline(s1, token, ':'); // get the IN
  getline(s1, token, ':'); // get the #
  size_t in_num(std::stoi(token));

  std::stringstream s2(bit_name);
  getline(s2, token, ':'); // get the BIT
  getline(s2, token, ':'); // get the #
  size_t bit_num(std::stoi(token));
  return input[in_num][bit_num];
}

void Circuit::_parse_output(std::string out_name, std::string bit_name,
                            bool value) {
  // output_name is OUT:#  bit_name is BIT:#

  std::stringstream s1(out_name);
  std::string token;
  getline(s1, token, ':'); // get the IN
  getline(s1, token, ':'); // get the #
  size_t out_num(std::stoi(token));

  std::stringstream s2(bit_name);
  getline(s2, token, ':'); // get the BIT
  getline(s2, token, ':'); // get the #
  size_t bit_num(std::stoi(token));
  circuitOut[out_num][bit_num] = value;
}

void Circuit::SetInput(Inputs input, bool verbose) {
  OPENFHE_DEBUG_FLAG(false);

  // parse input;
  // determine input dimensions
  auto n_inputs = input.size();
  std::vector<unsigned int> in_size(n_inputs);
  size_t ix = 0;
  size_t total_inputs = 0;
  size_t total_input_bits = 0;
  for (auto thisin : input) {
    in_size[ix] = thisin.size();
    if (verbose)
      std::cout << "setting input " << ix << " size " << in_size[ix]
                << std::endl;
    ix++;
    total_inputs++;
    total_input_bits += thisin.size();
  }

  if (verbose)
    std::cout << "set input total of " << total_inputs << " inputs"
              << std::endl;
  size_t inputs_used = 0;
  this->n_input_gates = 0;
  // for each gate on input gate list
  for (auto g : this->inputGates) {
    OPENFHE_DEBUG("parsing gate " << g.name);
    auto this_input = g.inWireNames[0];

    auto this_bit = g.inWireNames[1];

    auto value = _parse_input(input, this_input, this_bit);
    // auto n_out = g.outWireNames.size();
    this->n_input_gates++;
    // create output wires from gate output list
    for (auto outName : g.outWireNames) {
      Wire w;
      w.setName(outName);
      w.setValue(value);

      OPENFHE_DEBUG("in setInput setting wire " << outName << " to " << value);

      // find fanout
      auto it = this->nl.find(outName);
      if (it == this->nl.end()) {
        std::cerr << "error, could not find " << outName << " in netlist"
                  << std::endl;
      }
      w.setFanoutGates(it->second);
      if (encrypted_flag) {
        w.setCipherText(this->cc.Encrypt(this->sk, value));
      }

      // remove from wire name from waitingWire list
      auto oit = std::find(this->waitingWireNames.begin(),
                           this->waitingWireNames.end(), outName);
      if (oit == this->waitingWireNames.end()) {
        std::cerr << "error can't find wire in waitingWireList in SetInput()"
                  << std::endl;
      }
      this->waitingWireNames.erase(oit);

      // push onto activeWires queue
      this->activeWires.push_back(w);
      inputs_used++;
    }
  }
  if (total_input_bits != inputs_used) {
    std::cerr << "error: total_inputs: " << total_input_bits
              << " #used: " << inputs_used << std::endl;
  } else {
    if (verbose)
      std::cout << "input confirmed" << std::endl;
  }
}

Outputs Circuit::Clock(void) {
  TIC(auto t_total);
  unsigned int management_time = 0;
  unsigned int execution_time = 0;
  unsigned int total_time = 0;

  if (this->done) {
    std::cerr << "done ckt clocked! should reset" << std::endl;
    exit(-1);
  }
  while (!this->activeWires.empty() && !this->done) {
    std::cout << "\r                            " << std::flush;
    std::cout << "\r managing... " << std::flush;
    TIC(auto t_management);
    _CircuitManager(); // puts tasks on executingGate
    management_time += TOC_MS(t_management);
    // returns when none are left
    std::cout << "\r                            " << std::flush;
    std::cout << "\r executing... " << std::flush;
    TIC(auto t_execution);
    _ExecuteGates();
    execution_time += TOC_MS(t_execution);
    if (doneGates.size() == allGates.size()) {
      this->done = true;
    }
  }
  total_time = TOC_MS(t_total);
  // if very fast circuits...
  if (execution_time == 0)
    execution_time = 1;
  if (total_time == 0)
    total_time = 1;

  std::cout << std::endl
            << "### Total time " << total_time << " msec" << std::endl;
  std::cout << std::endl
            << "efficiency "
            << float(execution_time) / float(total_time) * 100.0 << "%"
            << std::endl;

  return this->circuitOut;
}

void Circuit::_CircuitManager(void) {
  OPENFHE_DEBUG_FLAG(false);
  TIC(auto t_tot);
  unsigned int cleanup_time = 0;
  unsigned int total_time = 0;

  // the basic flow is:
  // for each active wire pop it of the active queue
  //  compare against each waiting gate
  //    if waiting gate is in the wire's fanout
  //       prepare that gate input and check if gate is ready to put on the
  //       execute queue otherwise push it on the examined queue
  //    then remove it from that wire's fanout
  //  if the wire's fanout is not empty push it to the front of the active queue

  // get wire (note if list is empty, then move on to processing gates
  // and need to return to  wait
  OPENFHE_DEBUG("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
  while (!this->activeWires.empty()) {
    OPENFHE_DEBUG("CM top wg: " << waitingGates.size()
                                << " aw: " << activeWires.size());

    auto inw = this->activeWires.front();
    this->activeWires.pop_front();
    // OPENFHE_DEBUG("after pop # active wire "<< activeWires.size());
    // OPENFHE_DEBUG("### check wire "<<inw.getName() );
    if (waitingGates.empty()) {
      std::cerr << "error in CircuitManager: empty watingGates queue "
                << std::endl;
    }
    examinedGates.clear();
    bool wire_done = false;
    while (!wire_done && !waitingGates.empty()) { // short ckt for wire done
      auto g = waitingGates.front();
      waitingGates.pop_front();
      // OPENFHE_DEBUG("  ## examining gate "<<g.name);
      auto n_in = g.inWireNames.size();

      bool gateReady(true);
      auto f = inw.getFanoutGates();
      auto it = std::find(f.begin(), f.end(), g.name);
      if (it != f.end()) { // if g.name in inw.fanoutGates
        OPENFHE_DEBUG("  found gate " << g.name << " in fanout");
        for (uint ix = 0; ix < n_in; ix++) {
          if (g.inWireNames[ix] == inw.getName()) {
            // mark this gate input ready
            g.ready[ix] = true;
            // copy the value and the ciphertext
            g.encin[ix] = inw.getCipherText();
            g.plainin[ix] = inw.getValue();
            // OPENFHE_DEBUG("    input "<<ix );
          }
          gateReady &= g.ready[ix]; // any unready inputs turn this off
        }
        if (gateReady) {
          this->executingGates.push_back(g);
          OPENFHE_DEBUG("  ->execute:  " << this->executingGates.size());
        } else {
          examinedGates.push_back(g);
          OPENFHE_DEBUG("  ->examined: " << examinedGates.size());
        }
        // remove this gate from this wire’s fanout
        inw.updateFanoutGates(g.name);
        // OPENFHE_DEBUG("  updated wire fanout on "<<inw.getName()
        //   << " now length "
        //   << inw.getFanoutGates().size() );
        if (inw.getNumberFanoutGates() != 0) {
          // OPENFHE_DEBUG("  wire not done");
        } else {
          wire_done = true;
          // OPENFHE_DEBUG("  wire done");
        }
      } else {
        // gate was not in current wire fanout.
        examinedGates.push_back(g);
      } // end if it!=end
    }
    TIC(auto t_clean);
    // copy examined gates to waitingGates
    OPENFHE_DEBUG("cycling gates #executing " << executingGates.size());
    OPENFHE_DEBUG("cycling gates #examined " << examinedGates.size());
    OPENFHE_DEBUG("cycling gates #waiting " << waitingGates.size());
    OPENFHE_DEBUG("cycling gataes #done " << doneGates.size());

    for (auto it : boost::adaptors::reverse(examinedGates)) {
      waitingGates.push_front(it);
    }
    examinedGates.clear();
    OPENFHE_DEBUG("cycled gates # waiting now " << waitingGates.size());

    // push wire onto back of activeWires queue
    if (!wire_done) {
      activeWires.push_front(inw);
      OPENFHE_DEBUG("pushing wire onto active " << inw.getName());
    } else {
      OPENFHE_DEBUG("wire done " << inw.getName());
    }
    OPENFHE_DEBUG("bottom of while waiting gates size: "
                  << waitingGates.size() << " wire done " << wire_done);

    OPENFHE_DEBUG("------------------");
    cleanup_time += TOC_MS(t_clean);
  } // while active wire is not empty
  OPENFHE_DEBUG("Manager Done Cycle");
  // active wire was empty. return so we can cycle again.
  total_time += TOC_MS(t_tot);
  // std::cout<<std::endl<<"tot time "<<total_time <<"cleanup time
  // "<<cleanup_time<<std::endl;
}

void Circuit::_ExecuteGates(void) {
  OPENFHE_DEBUG_FLAG(false);
  // For each gate on the executeGate queue in parallel
  OPENFHE_DEBUG("Execute start Cycle");

  // all gates on the executingGates queue can be Evaluated in parallel
#if 0 // requires c++ 9.0 to compile  note could try using  __GNUC__ >8
#pragma omp parallel for schedule(dynamic)
  for (Gate & g: executingGates){
	OPENFHE_DEBUG("processing gate "<<g.name);
	g.Evaluate(this->gep);
  }
#else
#pragma omp parallel
  {
#pragma omp single
    {
      for (Gate &g : executingGates) {
#pragma omp task shared(g)
        {
          OPENFHE_DEBUG("processing gate " << g.name);
          g.Evaluate(this->gep);
        }
      }
    }
  }
#endif

  OPENFHE_DEBUG("done parallel gate");
  while (!this->executingGates.empty()) {
    // pop gate
    auto g = this->executingGates.front();
    this->executingGates.pop_front();
    // OPENFHE_DEBUG("execute gate" <<g.name);
    // process gate
    // g.Evaluate(this->plaintext_flag, this->encrypted_flag,
    // this->verify_flag);
    switch (g.op) {
    case (GateEnum::INPUT):
      this->n_input_gates++;
      break;
    case (GateEnum::OUTPUT):
      this->n_output_gates++;
      break;
    case (GateEnum::NOT):
      this->n_not_gates++;
      break;
    case (GateEnum::AND):
      this->n_and_gates++;
      break;
    case (GateEnum::OR):
      this->n_or_gates++;
      break;
    case (GateEnum::XOR):
      this->n_xor_gates++;
      break;
    case (GateEnum::DFF):
      break;
    case (GateEnum::LUT3):
      break;
    case (GateEnum::LUT4):
      break;
    default:
      std::cerr << "bad gate eval" << std::endl;
    }

    if (g.op != GateEnum::OUTPUT) { // output gates do not generate output wires
      auto outnames = g.outWireNames;
      unsigned int out_ix(0);
      for (auto outname : outnames) {
        OPENFHE_DEBUG("  activating gate " << g.name << " output wire "
                                           << outname);

        Wire w;
        w.setName(outname);
        if (this->plaintext_flag) {
          w.setValue(g.plainout[out_ix]);
        }
        if (this->encrypted_flag) {
          w.setCipherText(g.encout[out_ix]);
        }
        out_ix++;

        // find fanout
        auto it = this->nl.find(outname);
        if (it == this->nl.end()) {
          std::cerr << "error, could not find " << outname << " in netlist"
                    << std::endl;
        }
        // std::cout<<"found "<<it->first<<std::endl;
        // for (auto it: it->second){
        //	std::cout<<" "<<it;
        //}
        // std::cout<<std::endl;

        w.setFanoutGates(it->second);

        // remove from wire name from watitingWire list
        auto oit = std::find(this->waitingWireNames.begin(),
                             this->waitingWireNames.end(), outname);
        if (oit == this->waitingWireNames.end()) {
          std::cerr << "error can't find wire in waitingWireList in SetInput()"
                    << std::endl;
        }
        this->waitingWireNames.erase(oit);

        // push onto activeWires queue
        this->activeWires.push_back(w);
        OPENFHE_DEBUG("  pushed onto active queue size" << activeWires.size());
      } // for outnames
    } else {
      // gate is output
      // right now outputs are output, bit, and single value
      if (encrypted_flag) {
        lbcrypto::LWEPlaintext res;
        this->cc.Decrypt(this->sk, g.encout[0], &res);
        _parse_output(g.outWireNames[0], g.outWireNames[1], res);
      } else {
        if (!plaintext_flag) {
          std::cerr << "Error either encrypted or plaintext flag must be set"
                    << std::endl;
        }
        _parse_output(g.outWireNames[0], g.outWireNames[1], g.plainout[0]);
      }
    } // if gate is not OUTPUT

    OPENFHE_DEBUG("  gate " << g.name << " done");
    this->doneGates.push_back(g); // done with this gate
  }                               // end while
  OPENFHE_DEBUG("Execute done Cycle");
  std::cout << "\rProcessing: " << this->doneGates.size() << " of "
            << this->allGates.size() << std::flush;
}

void Circuit::setPlaintext(bool input) {
  this->plaintext_flag = input;
  this->gep.plaintext_flag = this->plaintext_flag;
}

bool Circuit::getPlaintext(void) { return (this->plaintext_flag); }

void Circuit::setEncrypted(bool input) {
  this->encrypted_flag = input;
  this->gep.encrypted_flag = this->encrypted_flag;
}

bool Circuit::getEncrypted(void) { return (this->encrypted_flag); }

void Circuit::setVerify(bool input) {
  this->verify_flag = input;
  this->gep.verify_flag = this->verify_flag;
  if (input) { // note in order to verify both flags must also be true
    this->setPlaintext(true);
    this->setEncrypted(true);
  }
}

bool Circuit::getVerify(void) { return (this->verify_flag); }

void Circuit::dumpNetList(void) {
  std::cout << "Netlist " << std::endl;
  for (auto it : this->nl) {
    std::cout << it.first;

    for (auto it2 : it.second) {
      std::cout << " " << it2;
    }
    std::cout << std::endl;
  }
}
void Circuit::dumpGates(void) {
  std::cout << "Inputlist " << std::endl;
  for (auto it : this->inputGates) {
    std::cout << it.name << std::endl;
  }
  std::cout << "Alllist " << std::endl;
  for (auto it : this->allGates) {
    std::cout << it.name << std::endl;
  }
}

void Circuit::dumpGateCount(void) {
  std::cout << "Number of input gates " << this->n_input_gates << std::endl;
  std::cout << "Number of output gates " << this->n_output_gates << std::endl;
  std::cout << "Number of not gates " << this->n_not_gates << std::endl;
  std::cout << "Number of and gates " << this->n_and_gates << std::endl;
  std::cout << "Number of or gates " << this->n_or_gates << std::endl;
  std::cout << "Number of xor gates " << this->n_xor_gates << std::endl;
}
