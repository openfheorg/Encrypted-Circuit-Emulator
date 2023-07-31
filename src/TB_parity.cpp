// @file TB_parity.cpp -- Test bed for encrypted parity circuits
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

//
//
// Test Bench script runs a simple circuit for an 8 bit
// parity generator/checker adder, and then run and test the result with the
// Encrypted Circuit Evaluator.
//
// Note that this runs a hand written script so there is no assembly or analysis
//
// Initial development was funded under DARPA MARSHAL
// List of Authors:
//    David Bruce Cousins
//
// Version History:
//   current version started 8/16/20 by D. Cousins dcousins@njit.edu
//
// Known Issues:
//   None.
//

#include <iostream>
#include <string>

#include "analyze.h"
#include "assemble.h"
#include "binfhecontext.h"
#include "test_parity.h"
#include "utils.h"

int main(int argc, char **argv) {
  // default parameters
  unsigned int num_test_loops = 10;
  lbcrypto::BINFHE_PARAMSET set(lbcrypto::STD128);
  lbcrypto::BINFHE_METHOD method(lbcrypto::GINX);
  bool verbose(false);

  // note parse inputs has several parameters we do not use in this simple case.

  bool dummy1, dummy2, dummy3;
  unsigned int dummy4;
  parse_inputs(argc, argv, &dummy1, &dummy2, &dummy3, &verbose, &set, &method,
               &dummy4, &num_test_loops);

  std::cout << "Test bench for simple parity circuit" << std::endl;

  std::string inputFname;
  std::string outputFname;
  std::string dirPath;

  // bool new_flag(false);

  bool all_passed = true;
  dirPath = "examples/simple_ckts/parity";
  outputFname = "parity.out";
  outputFname = dirPath + "/" + outputFname;

  insureFileExists(outputFname);

  bool passed;
  passed = test_parity(outputFname, num_test_loops, set, method);
  all_passed = all_passed && passed;

  std::cout << "===========================" << std::endl;
  std::cout << outputFname << " ";
  if (passed) {
    std::cout << "passes" << std::endl;
  } else {
    std::cout << "fails" << std::endl;
  }
}
