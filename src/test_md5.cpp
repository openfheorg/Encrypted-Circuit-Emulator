// @file test_md5.cpp -- runs and tests encrypted md5 crypto circuit
//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include "test_md5.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>

#include "circuit.h"
#include "utils.h"

/////

//
// test program to run circuits for
// various md5 operations provided at
// <https://homes.esat.kuleuven.be/~nsmart/MPC/>
// Initial development was funded under DARPA MARSHAL
//
// Converted from matlab code originally written for DARPA Proceed
// Version History:
//   original matlab  started 12/12/2012 by D. Cousins
//   current version started 7/20/2012 by D. Cousins dcousins@njit.edu
// Known Issues:
//   we do not have sha1 test vectors so we cannot run those tests.
//
//
// List of Authors:
//    original David Bruce Cousins, dcousins@bbn.com now of njit.edu

// Description:
// This testbed takes an assembled circuit description program for the
// ECE and tests it in a loop. It scans the input file, determines
// I/O.  It then generates a random input set, and computes the
// appropriate output. It then runs the program through the ECE and
// compares results.
//
// Input
//   inFname = input filename containing the program
//   numTestLoops = number of times to test program
// Output
//   passed = if true then all tests passed
//
// Version History:
//   v01 matlab started 12/06/2012 by D. Cousins
//   c++ port started 7/28/2020
//
// Known Issues:
//   only MD5 and SHA256 have valid test vectors provided so all other
//   crypto circuits were ignored
//

bool test_md5(std::string inFname, unsigned int numTestLoops,
                 lbcrypto::BINFHE_PARAMSET set,
                 lbcrypto::BINFHE_METHOD method) {

  std::cout << "test_md5: Opening file " << inFname
            << " for test_md5 parameters" << std::endl;

  // open the program file to determine some parameters for tests
  std::ifstream inFile;
  // Set exceptions to be thrown on failure
  inFile.exceptions(std::ifstream::failbit | std::ifstream::badbit);

  try {
    inFile.open(inFname.c_str());
  } catch (std::system_error &e) {
    std::cerr << e.code().message() << std::endl;
    exit(-1);
  }

  std::string tline;

  unsigned int max_n_reg;
  std::vector<unsigned int> n_in_bits(2);
  std::vector<unsigned int> n_out_bits(1);
  unsigned int n_p_passed(0);
  unsigned int n_e_passed(0);

  //  get input and output statistics from file
  try {
    while (std::getline(inFile, tline)) {
      if (tline.find("# Assembler statistics") != std::string::npos) {
        std::getline(inFile, tline); // skip 3 lines
        std::getline(inFile, tline);
        std::getline(inFile, tline);
        std::getline(inFile, tline);

        sscanf(tline.c_str(), "# %ul registers used\n", &max_n_reg);
        std::cout << "using " << max_n_reg << " registers" << std::endl;

      } else if (tline.find("# number input") != std::string::npos) {
        // note hardwired for two inputs
        unsigned int tmp;
        sscanf(tline.c_str(), "# number input1 bits %d\n", &tmp);
        n_in_bits[0] = tmp;
        std::cout << "using " << n_in_bits[0] << " bits for input 1"
                  << std::endl;

        std::getline(inFile, tline);

        sscanf(tline.c_str(), "# number input2 bits %d\n", &tmp);
        n_in_bits[1] = tmp;
        std::cout << "using " << n_in_bits[1] << " bits for input 2"
                  << std::endl;

        // different files have different numbers of inputs
        // unsigned int n_inputs(0);
        // if (n_in_bits[1] == 0) {
        //   n_inputs = 1;
        // } else {
        //   n_inputs = 2;
        // }
      } else if (tline.find("# number output") != std::string::npos) {
        // note hardwired for one output

        unsigned int tmp;
        sscanf(tline.c_str(), "# number output1 bits %d\n", &tmp);
        n_out_bits[0] = tmp;
        std::cout << "using " << n_out_bits[0] << " bits for output 1"
                  << std::endl;
      }
    }
  } catch (std::system_error &e) {
    std::cout << "end of file" << std::endl;
  }
  try {
    inFile.close();
  } catch (std::system_error &e) {
    std::cerr << e.code().message() << std::endl;
    exit(-1);
  }

  Circuit circ(set, method);
  bool success = circ.ReadFile(inFname);
  if (!success) {
    std::cout << "error parsing file " << inFname << std::endl;
  }

  // circ.dumpNetList();
  // circ.dumpGates();

  //  loop over tests
  bool passed = true;

  // preallocate input and output
  std::vector<unsigned int> out(n_out_bits[0], 0);

  // generate the test output (md5)

  std::vector<unsigned int> in_good(n_in_bits[0], 0);
  std::vector<unsigned int> out_good(n_out_bits[0], 0);
  std::string inhex, outhex;

  // note this test code is slightly different from others in that
  // each tested ckt  has different i/o and preloaded test vectors.

  Inputs inputs;
  for (uint test_ix = 0; test_ix < numTestLoops; test_ix++) {
    std::cout << "test " << test_ix << std::endl;

    if (contains(inFname, "md5")) { // test md5
      std::cout << "md5: " << std::endl;
      unsigned int nloop = 4; //# iput vectors we have
      for (uint loop_ix = 0; loop_ix < nloop; loop_ix++) {
        std::cout << "subtest " << loop_ix << std::endl;
        switch (loop_ix) {
        case 0:
          inhex =
              "00000000000000000000000000000000000000000000000000000000000000"
              "00000000000000000000000000000000000000000000000000000000000000"
              "0000";
          outhex = "ac1d1f03d08ea56eb767ab1f91773174";
          break;
        case 1:
          inhex =
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
              "1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d"
              "3e3f";
          outhex = "cad94491c9e401d9385bfc721ef55f62";
          break;
        case 2:
          inhex =
              "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              "ffff";
          outhex = "b487195651913e494b55c6bddf405c01";
          break;
        case 3:
          inhex =
              "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c"
              "89452821e638d01377be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5b547"
              "0917";
          outhex = "3715f568f422db75cc8d65e11764ff01";
          break;
        default:
          std::cout << "bad md5 test case number:" << loop_ix << std::endl;
          exit(-1);
        }

        // 512 bits for input 1, 0 for input 2
        // 128 bits for output 1
        in_good = HexStr2UintVec(inhex); // convert to input

        if (in_good.size() != n_in_bits[0]) {
          std::cout << "bad md5 input 1 length " << std::endl;
          exit(-1);
        }
        std::cout << " input 1:  ";
        for (int ix = n_in_bits[0] - 1; ix >= 0; ix--) {
          std::cout << in_good[ix];
        }

        std::cout << std::endl;

        out_good = HexStr2UintVec(outhex); // clear output
        // note the provided test vectors are reversed from our circuit,
        // so we reverse the input and output
        reverse(in_good.begin(), in_good.end());
        reverse(out_good.begin(), out_good.end());

        // pack in_good into Inputs
        inputs.resize(1); // only one input
        inputs[0].resize(0);

        for (uint ix = 0; ix < n_in_bits[0]; ix++) {
          inputs[0].push_back(in_good[ix]);
        }
        auto out_plain = out_good;

        //  execute program in circuit

        std::cout << "executing circuit" << std::endl;
        circ.Reset();
        circ.setPlaintext(true);
        circ.setEncrypted(false);
        circ.setVerify(false);
        circ.SetInput(inputs);
        Outputs outputs = circ.Clock();
        if (test_ix == 0)
          circ.dumpGateCount();
        std::cout << "program done" << std::endl;

        // parse the output structure
        for (auto outreg : outputs) {
          unsigned int bit_ix = 0;
          for (auto outbit : outreg) {
            out_plain[bit_ix] = outbit;
            bit_ix++;
          }
        }

        //// compare output with known good answer
        if (out_plain == out_good) {
          std::cout << "output match" << std::endl;
          n_p_passed++;
          passed = passed & true;
        } else {
          std::cout << "comp output: ";
          for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
            std::cout << out_plain[ix] << " " << out_good[ix] << std::endl;
          }
          std::cout << std::endl;

          std::cout << "output does not match" << std::endl;
          passed = passed & false;
        }

        std::cout << "executing Encrypted program" << std::endl;
        //  execute program in encrypted circuit evaluator

        //  execute program in encrypted circuit evaluator

        std::cout << "executing encrypted circuit" << std::endl;
        circ.Reset();
        circ.setPlaintext(false);
        circ.setEncrypted(true);
        circ.setVerify(true);
        circ.SetInput(inputs);
        outputs = circ.Clock();
        // circ.dumpGateCount();
        std::cout << "program done" << std::endl;
        auto out_enc = out;

        for (auto outreg : outputs) {
          unsigned int bit_ix = 0;
          for (auto outbit : outreg) {
            out_enc[bit_ix] = outbit;
            bit_ix++;
          }
        }

        //  compare plaintext output with known good answer
        if (out_enc == out_good) {
          std::cout << "output match " << std::endl;
          passed = passed & true;
          n_e_passed++;
        } else {
          std::cout << "enc computed  out: ";
          for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
            std::cout << out_enc[ix];
          }
          std::cout << std::endl;
          std::cout << "output does not match" << std::endl;
          passed = passed & false;
        }
      } // test loop

    } else {
      std::cout << "cannot generate test input for case " << inFname
                << std::endl;
      passed = 0;
    }

  } // for test_ix
  std::cout << "# tests total: " << numTestLoops << std::endl;
  std::cout << "# passed plaintext: " << n_p_passed << std::endl;
  std::cout << "# passed encrypted: " << n_e_passed << std::endl;

  return passed;
}