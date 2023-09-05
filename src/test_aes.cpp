// @file test_adder.cpp -- runs and tests encrypted adder circuits
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

#include <cstring>
#include <fstream>
#include <iostream>

#include "circuit.h"
#include "test_aes.h"
#include "utils.h"
#include <algorithm>
#include <functional>

/////
// DARPA MARSHAL
//
//
// test program to run circuits for
// various aes operations provided at
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
// these outputs have not been validated.
// generalize input output: in1 in2 should become one 2d vector. #shoudl be 0, 1

bool test_aes(std::string inFname, unsigned int numTestLoops,
              lbcrypto::BINFHE_PARAMSET set, lbcrypto::BINFHE_METHOD method) {
  // BLU_test_aes: tests BLU with aes programs
  std::cout << "test_aes: Opening file " << inFname
            << " for test_aes parameters" << std::endl;

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
    std::cerr << "error parsing file " << inFname << std::endl;
  }

  bool passed = true;

  // preallocate input and output
  std::vector<unsigned int> out(n_out_bits[0], 0);

  // generate the test output (aes)

  std::vector<unsigned int> in1_good(n_in_bits[0], 0);
  std::vector<unsigned int> in2_good(n_in_bits[1], 0);
  std::vector<unsigned int> out_good(n_out_bits[0], 0);
  std::string inhex1, inhex2, outbin;

  Inputs inputs;
  for (uint test_ix = 0; test_ix < numTestLoops; test_ix++) {
    std::cout << "test " << test_ix << std::endl;
    unsigned int nloop = 2; //# input vectors we have
    for (uint loop_ix = 0; loop_ix < nloop; loop_ix++) {
      std::cout << "subtest " << loop_ix << std::endl;
      switch (loop_ix) {
      case 0:
        if (contains(inFname, "AES-expanded")) { // test aes-expanded
          inhex1 = "00000000000000000000000000000000";
          inhex2 = "00000000000000000000000000000000000000000000000000000000000"
                   "00000000000000000000000000000000000000000000000000000000000"
                   "00000000000000000000000000000000000000000000000000000000000"
                   "00000000000000000000000000000000000000000000000000000000000"
                   "00000000000000000000000000000000000000000000000000000000000"
                   "000000000000000000000000000000000000000000000000000000000";
          // not validated
          outbin = "01101100011011000110110001101100011011000110110001101100011"
                   "01100011011000110110001101100011011000110110001101100011011"
                   "0001101100";
        } else { // non-expanded
          inhex1 = "00000000000000000000000000000000";
          inhex2 = "00000000000000000000000000000000";
          // not validated
          outbin = "01110100110101000010110001010011100110100101111100110010000"
                   "10001110111000011010001010001111101110010101111010010100101"
                   "1101100110";
        }
        break;
      case 1:
        if (contains(inFname, "AES-expanded")) { // test aes-expanded
          inhex1 = "ffffffffffffffffffffffffffffffff";
          inhex2 = "ffffffffffffffffffffffffffffffff";
          inhex2 = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                   "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                   "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                   "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                   "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                   "fffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
          // not validated
          outbin = "00110010001100100011001000110010001100100011001000110010001"
                   "10010001100100011001000110010001100100011001000110010001100"
                   "1000110010";
        } else { // non-expanded
          inhex1 = "ffffffffffffffffffffffffffffffff";
          inhex2 = "ffffffffffffffffffffffffffffffff";
          // not validated
          outbin = "10011110100111010101110010011000010010100000111010001010010"
                   "01101000011001111001100000001010011010011111010000100111111"
                   "0100111101";
        }
        break;
      default:
        std::cout << "bad aes test case number:" << loop_ix << std::endl;
        exit(-1);
      }

      // non-expanded 128 bits for input 1, 2
      // expanded 128 bits for input 1 1408 for input 2
      // 128 bits for output 1

      in1_good = HexStr2UintVec(inhex1); // convert to input
      in2_good = HexStr2UintVec(inhex2); // convert to input

      if (in1_good.size() != n_in_bits[0]) {
        std::cout << "bad aes input 1 length " << std::endl;
        exit(-1);
      }
      std::cout << " input 1:  ";
      for (int ix = n_in_bits[0] - 1; ix >= 0; ix--) {
        std::cout << in1_good[ix];
      }
      std::cout << std::endl;

      if (in2_good.size() != n_in_bits[1]) {
        std::cout << "bad aes input 2 length " << std::endl;
        exit(-2);
      }
      std::cout << " input 2:  ";
      for (int ix = n_in_bits[1] - 1; ix >= 0; ix--) {
        std::cout << in2_good[ix];
      }
      std::cout << std::endl;

      out_good = BinStr2UintVec(outbin); // set output
      // note the provided test vectors are reversed from our circuit,
      // so we reverse the input and output
      // reverse(in1_good.begin(), in1_good.end());
      // reverse(in2_good.begin(), in2_good.end());
      // reverse(out_good.begin(), out_good.end());

      // pack in1_good in2_good into Inputs
      inputs.resize(2); // two inputs
      inputs[0].resize(0);
      inputs[1].resize(0);

      for (uint ix = 0; ix < n_in_bits[0]; ix++) {
        inputs[0].push_back(in1_good[ix]);
      }
      for (uint ix = 0; ix < n_in_bits[1]; ix++) {
        inputs[1].push_back(in2_good[ix]);
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
        std::cout << "circuit output: ";
        for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
          std::cout << out_plain[ix];
        }
        std::cout << std::endl;

        std::cout << "good output: ";
        for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
          std::cout << out_good[ix];
        }
        std::cout << std::endl;

        std::cout << "output does not match" << std::endl;
        passed = passed & false;
#if 0
		std::cout<<"comp output: ";
		for (int ix=n_out_bits[0]-1; ix>=0; ix--) {
		  std::cout<<out_plain[ix] << " " <<out_good[ix] <<std::endl;
		}
		std::cout<< std::endl;
#endif
      }

      std::cout << "executing Encrypted program" << std::endl;
      //  execute program in encrypted circuit evaluator

      std::cout << "executing encrypted circuit" << std::endl;
      circ.Reset();
      circ.setPlaintext(false);
      circ.setEncrypted(true);
      circ.setVerify(false); //adds time for decryption of partial results
      circ.SetInput(inputs);
      outputs = circ.Clock();

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
  }   // for test_ix
  std::cout << "# tests total: " << numTestLoops << std::endl;
  std::cout << "# passed plaintext: " << n_p_passed << std::endl;
  std::cout << "# passed encrypted: " << n_e_passed << std::endl;

  return passed;
}
