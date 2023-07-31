// @file TB_md5.cpp -- Test bed for encrypted md5 crypto circuits
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
//
// Test Bench script to parse and assemble  circuits for
// md5 example crypto function provided by
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
//   PALISADE version 7/20/2012 by D. Cousins dcousins@njit.edu
//   11/7/2022 TB_crypto split into TB_md5 and TB_sha256 to reduce runtime

// Known Issues:

//   Analysis and Assembly currently work only with "old style bristol
//   circuits".
//   Only MD5 and SHA256 have valid test vectors provided so all other
//   crypto circuits were ignored
//

#include <iostream>
#include <string>

#include "binfhecontext.h"

#include "analyze.h"
#include "assemble.h"
#include "test_md5.h"
#include "utils.h"

int main(int argc, char **argv) {
  std::cout << "Test bench for md5 " << std::endl;

  bool analyze_flag = false;
  bool gen_fan_flag = false;
  bool assemble_flag = true && analyze_flag; // cant assemble without analysis

  unsigned int n_cases = 1;
  unsigned int num_test_loops = 10;

  lbcrypto::BINFHE_PARAMSET set(lbcrypto::STD128);
  lbcrypto::BINFHE_METHOD method(lbcrypto::GINX);
  bool verbose(false);

  parse_inputs(argc, argv, &assemble_flag, &gen_fan_flag, &analyze_flag,
               &verbose, &set, &method, &n_cases, &num_test_loops);
  // note n_cases is ignored
  if (n_cases != 1) {
    std::cout << "Note n_cases is ignored for this Test Bench" << std::endl;
  }

  std::string inputFname;
  std::string outputFname;
  std::string dirPath;
  uint64_t max_depth =
      0; // max depth supported before bootstrap needed  0 means FHE

  bool new_flag(false);

  dirPath = "examples/old_bristol_ckts/crypto";
  inputFname = "md5.txt";
  outputFname = "md5_";

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
    bool debug_flag = true; // annotate assembler output

    //  now assemble note this writes out a new version of .out

    std::cout << "assembling " << inputFname << std::endl;
    assemble_bristol(analysis_result, max_depth, debug_flag);
  }

  insureFileExists(outputFname);

  bool passed;
  passed = test_md5(outputFname, num_test_loops, set, method);

  std::cout << "===========================" << std::endl;
  std::cout << outputFname << " ";
  if (passed) {
    std::cout << " passes" << std::endl;
  } else {
    std::cout << " fails" << std::endl;
  }
  std::cout << "===========================" << std::endl;
}
