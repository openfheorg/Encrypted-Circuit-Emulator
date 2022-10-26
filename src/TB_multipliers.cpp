// @file TB_multipliers.cpp -- Test bed for encrypted multiplier circuits
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2020, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

////

//
//
// Test Bench script to parse and assemble circuits for
// example multiplier functions provided by
// <https://homes.esat.kuleuven.be/~nsmart/MPC/>, and then run and test the
// result with an encrypted circuit evaluator.
//
// Initial development was funded under DARPA MARSHAL
//
// Converted from matlab code originally written for DARPA Proceed
// List of Authors:
//    David Bruce Cousins
//
// Version History:
//   original matlab  started 12/12/2012 by D. Cousins
//   current version started 7/20/2012 by D. Cousins dcousins@njit.edu

// Known Issues:
//   Analysis and Assembly currently work only with "old style bristol circuits"
//

#include <iostream>
#include <string>

#include "binfhecontext.h"

#include "analyze.h"
#include "assemble.h"
#include "test_multiplier.h"
#include "utils.h"

int main(int argc, char **argv) {
  std::cout << "Test bench for multipliers" << std::endl;

  bool analyze_flag = false;
  bool gen_fan_flag = false;
  bool assemble_flag = true && analyze_flag;  // cant assemble without analysis

  unsigned int n_cases = 1;
  unsigned int num_test_loops = 10;

  lbcrypto::BINFHE_PARAMSET set(lbcrypto::STD128_OPT);
  lbcrypto::BINFHE_METHOD method(lbcrypto::GINX);
  bool verbose(false);

  parse_inputs(argc, argv, &assemble_flag, &gen_fan_flag, &analyze_flag,
               &verbose, &set, &method, &n_cases, &num_test_loops);

  std::string inputFname;
  std::string outputFname;
  std::string dirPath;
  uint64_t max_depth = 0;  // max depth supported before bootstrap needed
  bool new_flag(false);
  bool all_passed = true;
  for (unsigned int i = 0; i < n_cases; i++) {
    switch (i) {
      case 0:
        dirPath = "examples/old_bristol_ckts/arith";
        inputFname = "mult_32x32.txt";
        outputFname = "mult_32x32_";
        break;
      default:
        std::cout << "bad case number:" << i << std::endl;
        exit(-1);
    }
    if (max_depth == 0) {
      outputFname = outputFname + "FHE.out";
    } else {
      outputFname = outputFname + std::to_string(max_depth) + ".out";
    }

    Analysis analysis_result;
    // analyze the circuit file for the case
    inputFname = dirPath + "/" + inputFname;
    outputFname = dirPath + "/" + outputFname;
    if (analyze_flag) {
      std::cout << "analyzing " << inputFname << std::endl;
      analysis_result = analyze_bristol(inputFname, gen_fan_flag, new_flag);
    }

    if (assemble_flag) {
      // generate assembler
      bool debug_flag = true;  // annotate assembler output

      //  now assemble note this writes out a new version of .out

      std::cout << "assembling " << inputFname << std::endl;
      assemble_bristol(analysis_result, max_depth, debug_flag);
    }

    insureFileExists(outputFname);

    bool passed;
    passed = test_multiplier(outputFname, num_test_loops, set, method);
    all_passed = all_passed && passed;

    std::cout << "===========================" << std::endl;
    std::cout << outputFname << " ";
    if (passed) {
      std::cout << "passes" << std::endl;
    } else {
      std::cout << "fails" << std::endl;
    }
  }  // loop over case i
  std::cout << "===========================" << std::endl;
  if (all_passed) {
    std::cout << "All Multiplier cases passed" << std::endl;
  } else {
    std::cout << "Some Multiplier cases failed" << std::endl;
  }
  std::cout << "===========================" << std::endl;
}
