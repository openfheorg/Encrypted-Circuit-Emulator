// @file test_parity.cpp -- runs and tests encrypted parity circuits
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

#include "test_parity.h"

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
// parity
// Initial development was funded under DARPA MARSHAL
//

// Description:
// This testbed  takes an assembled circuit description program for the ECE and
// tests it in a loop. It scans the input file, determines I/O.  It then
// generates a random input set, and computes the appropriate output. It then
// runs the program through the ECE and compares results. We generate a random 8
// bit input, and compute the parity (the 9th input bit is set to zero, as that
// can be used to compute parity of wider data via cascade). That computation is
// done plaintext and encrypted. Next we set the 9th bit such that the encrypted
// data has odd parity [done by  setting the 9th bit to the value of the even
// output indicator] and this input run through the circuit evaluator again. the
// result should be that the odd parity indicator is 1 and even is 0. The
// overall flow is: data -> parity generation -> data+parity bit -> parity
// checking
//
//
// Input
//   inFname = input filename containing the program
//   numTestLoops = number of times to test program
// Output
//   passed = if true then all tests passed
//
// Version History:
// Known Issues:
//   None.
//

bool test_parity(std::string inFname, unsigned int numTestLoops,
                 lbcrypto::BINFHE_PARAMSET set,
                 lbcrypto::BINFHE_METHOD method) {
  // BLU_test_parity: tests BLU with parity programs
  std::cout << "test_parity: Opening file " << inFname
            << " for test_parity parameters" << std::endl;

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

  // unsigned int max_n_reg;
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
    std::cout << "error parsing file " << inFname << std::endl;
  }

  // circ.dumpNetList();
  // circ.dumpGates();

  //  loop over tests
  bool passed = true;

  // preallocate input and output

  std::vector<unsigned int> in1(n_in_bits[0]);

  Inputs inputs;
  std::cout << "testing " << numTestLoops << " iterations" << std::endl;
  for (uint test_ix = 0; test_ix < numTestLoops; test_ix++) {
    unsigned int in_uint(0);

    std::cout << "test " << test_ix << std::endl;

    // generate random inputs
    srand(test_ix); // set the random number generator to a known seed
    std::cout << " input 1:  ";
    inputs.resize(1); // clear input
    inputs[0].resize(0);
    for (uint ix = 0; ix < n_in_bits[0]; ix++) {
      if (ix == n_in_bits[0] - 1) {
        // last input bit is always 0 (or cascade from other byte)
        in1[ix] = 0;
      } else {
        in1[ix] = rand() % 2;
      }
      inputs[0].push_back(in1[ix]);
      in_uint += in1[ix] << ix;
    }

    for (int ix = n_in_bits[0] - 1; ix >= 0; ix--) {
      std::cout << in1[ix];
    }

    std::cout << " = " << in_uint << std::endl;
    std::cout << std::endl;

    // generate the test output (sum)
    unsigned int even(0);
    unsigned int odd(0);
    std::vector<unsigned int> out(n_out_bits[0], 0);
    odd = __builtin_parity(in_uint);
    even = !odd;

    out[0] = even;
    out[1] = odd;
    std::cout << " output : ";
    for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
      std::cout << out[ix];
    }
    if (even) {
      std::cout << " even ";
    } else {
      std::cout << " odd ";
    }
    std::cout << std::endl;
    auto out_good = out;

    //  execute program in circuit

    std::cout << "executing circuit" << std::endl;
    circ.Reset();
    circ.setPlaintext(true);
    circ.setEncrypted(false);
    circ.setVerify(false);
    circ.SetInput(inputs);
    Outputs outputs = circ.Clock();
    std::cout << "program done" << std::endl;
    if (test_ix == 0)
      circ.dumpGateCount();

    auto out_plain = out;
    // note curently only one valid output register
    for (auto outreg : outputs) {
      unsigned int bit_ix = 0;
      for (auto outbit : outreg) {
        out_plain[bit_ix] = outbit;
        bit_ix++;
      }
    }

    //  compare plaintext output with known good answer
    if (out_plain == out_good) {
      std::cout << "output match " << std::endl;
      n_p_passed++;
      passed = passed & true;
    } else {
      std::cout << "plain computed  out: ";
      for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
        std::cout << out_plain[ix];
      }
      std::cout << std::endl;
      std::cout << "output does not match" << std::endl;
      passed = passed & false;
    }
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
    // map output registers
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

    // combine the input data with the parity bit and test it.
    // note high bit was set to zero.
    inputs[0][n_in_bits[0] - 1] = even; // should now be odd parity

    auto out2_good = out;
    out2_good[0] = 0;
    out2_good[1] = 1; // should now have odd parity detected

    //  run parity tester

    std::cout << "executing circuit" << std::endl;
    circ.Reset();
    circ.setPlaintext(true);
    circ.setEncrypted(false);
    circ.setVerify(false);
    circ.SetInput(inputs);
    outputs = circ.Clock();
    std::cout << "program done" << std::endl;
    if (test_ix == 0)
      circ.dumpGateCount();

    auto out2_plain = out;
    // note curently only one valid output register
    for (auto outreg : outputs) {
      unsigned int bit_ix = 0;
      for (auto outbit : outreg) {
        out2_plain[bit_ix] = outbit;
        bit_ix++;
      }
    }

    //  compare plaintext output with known good answer
    if (out2_plain == out2_good) {
      std::cout << "output match " << std::endl;
      n_p_passed++;
      passed = passed & true;
    } else {
      std::cout << "plain computed  out: ";
      for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
        std::cout << out2_plain[ix];
      }
      std::cout << std::endl;
      std::cout << "output does not match" << std::endl;
      passed = passed & false;
    }
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
    auto out2_enc = out;
    // map output registers
    for (auto outreg : outputs) {
      unsigned int bit_ix = 0;
      for (auto outbit : outreg) {
        out2_enc[bit_ix] = outbit;
        bit_ix++;
      }
    }
    //  compare plaintext output with known good answer
    if (out2_enc == out2_good) {
      std::cout << "output match " << std::endl;
      passed = passed & true;
      n_e_passed++;
    } else {
      std::cout << "enc computed  out: ";
      for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
        std::cout << out2_enc[ix];
      }
      std::cout << std::endl;
      std::cout << "output does not match" << std::endl;
      passed = passed & false;
    }
  } // for test_ix
  std::cout << "# tests total: " << numTestLoops << std::endl;
  std::cout << "note the following is max of 2x # tests " << std::endl;

  std::cout << "# passed plaintext: " << n_p_passed << std::endl;
  std::cout << "# passed encrypted: " << n_e_passed << std::endl;

  return passed;
}
