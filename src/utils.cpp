// @file utils.cpp -- utility functions for encrypted circuit evaluation
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

#include "utils.h"

#include <getopt.h>

#include <bitset>
#include <iostream>
#include <sstream>
#include <string>

bool contains(std::string s1, std::string s2) {
  return s1.find(s2) != std::string::npos;
}

std::vector<unsigned int> HexStr2UintVec(std::string inhex) {
  unsigned int in_len = inhex.length(); // number of hex digits
  unsigned out_len = in_len * 4;        // number of bits
  std::vector<unsigned int> out_bits(out_len, 0);
  unsigned int out_ix = 0;

  // iterate backwards over the input string
  for (auto it = inhex.crbegin(); it != inhex.crend(); ++it) {
    std::stringstream ss;

    ss << std::hex << *it;
    unsigned int n;
    ss >> n;
    const unsigned int nbitnibble(4);
    std::bitset<nbitnibble> b(n);
    // iterate  over bitset
    for (uint bix = 0; bix < nbitnibble; bix++) {
      out_bits[out_ix] = b.test(bix);
      out_ix++;
    }
  }
  return (out_bits);
}

std::vector<unsigned int> BinStr2UintVec(std::string inbin) {
  unsigned int in_len = inbin.length(); // number of binary digits
  unsigned out_len = in_len;            // number of bits
  std::vector<unsigned int> out_bits(out_len, 0);
  unsigned int out_ix = 0;

  // iterate backwards over the input string
  char *w = new char[2];
  for (auto it = inbin.crbegin(); it != inbin.crend(); ++it) {
    w[0] = *it;
    w[1] = '\0'; // null terminate
    out_bits[out_ix] = std::stoi(w);
    out_ix++;
  }
  delete[] w;
  return (out_bits);
}

std::string UintVec2str(std::vector<unsigned int> in) {
  unsigned int in_len = in.size(); // number of bits
  std::string outstr;
  std::cout << "in ";
  for (auto i : in) {
    std::cout << i << ' ';
  }
  std::cout << std::endl;
  // unsigned int in_ix = 0;

  // iterate over the input vector
  const unsigned int nbitbyte(8);
  for (uint ix = 0; ix < in_len;) {
    std::bitset<nbitbyte> b(0);
    // iterate  over bitset
    for (uint bix = 0; bix < nbitbyte; bix++) {
      b.set(bix, in[ix]);
      ix++;
    }
    outstr.push_back((char)b.to_ulong());
  }
  std::cout << "out" << std::hex;
  for (auto c : outstr) {
    std::cout << (uint)c << ' ';
  }

  std::cout << std::endl;

  return (outstr);
}

void parse_inputs(int argc, char **argv, bool *assemble_flag,
                  bool *gen_fan_flag, bool *analyze_flag, bool *verbose,
                  lbcrypto::BINFHE_PARAMSET *set,
                  lbcrypto::BINFHE_METHOD *method, unsigned int *n_cases,
                  unsigned int *num_test_loops) {
  // manage the command line args
  int opt; // option from command line parsing

  std::string usage_string =
      std::string("run ") + std::string(argv[0]) +
      std::string(
          " demo with settings (default value show in parenthesis):\n") +
      std::string("-a assemble flag (false) note, if true then analyze must be "
                  "true\n") +
      std::string("-f fanout generation flag (false)\n") +
      std::string("-z analyze flag (false)\n") +
      std::string("-c # test cases (not used in all TB programs\n") +
      std::string("-n # test loops [10]\n") +
      std::string("-s parameter set (TOY|STD128Q_LMKCDEY) [STD128Q_LMKCDEY]\n") +
      std::string("-m method (AP|GINX|LMKCDEY) [LMKCDEY] \n") +
      std::string("-v verbose flag (false)\n") +
      std::string("\nh prints this message\n");

  int num_test_loops_in;
  int n_cases_in;

  while ((opt = getopt(argc, argv, "azfc:s:m:n:vh")) != -1) {
    std::string set_str;
    std::string method_str;

    switch (opt) {
    case 'a':
      *assemble_flag = true;
      std::cout << "assembling" << std::endl;
      break;
    case 'f':
      *gen_fan_flag = true;
      std::cout << "fan_flag true" << std::endl;
      break;
    case 'z':
      *analyze_flag = true;
      std::cout << "analyzing" << std::endl;
      break;
    case 's':
      set_str = optarg;
      if (set_str == "STD128Q_LMKCDEY") {
        *set = lbcrypto::STD128Q_LMKCDEY;
        std::cout << "using STD128Q_LMKCDEY" << std::endl;
      } else if (set_str == "TOY") {
        *set = lbcrypto::TOY;
        std::cout << "using TOY" << std::endl;
      } else {
        std::cerr << "Error Bad Set chosen" << std::endl;
        exit(-1);
      }
      break;
    case 'm':
      method_str = optarg;
      if (method_str == "GINX") {
        *method = lbcrypto::GINX;
        std::cout << "using GINX" << std::endl;
      } else if (method_str == "AP") {
        *method = lbcrypto::AP;
        std::cout << "using AP" << std::endl;
	  } else if (method_str == "LMKCDEY") {
        *method = lbcrypto::LMKCDEY;
        std::cout << "using LMKCDEY" << std::endl;
      } else {
        std::cerr << "Error Bad Method chosen" << std::endl;
        exit(-1);
      }
      break;
    case 'c':
      n_cases_in = atoi(optarg);
      if (n_cases_in < 0) {
        *n_cases = 1;
      } else {
        *n_cases = n_cases_in;
      }
      std::cout << "n_cases set to " << *n_cases << std::endl;
      break;
    case 'n':
      num_test_loops_in = atoi(optarg);
      if (num_test_loops_in < 0) {
        *num_test_loops = 1;
      } else {
        *num_test_loops = num_test_loops_in;
      }
      std::cout << "num_test_loops set to " << *num_test_loops << std::endl;
      break;
    case 'v':
      *verbose = true;
      std::cout << "verbose" << std::endl;
      break;
    case 'h':
    default: /* '?' */
      std::cout << usage_string << std::endl;
      exit(0);
    }
  }
  *assemble_flag = true && *analyze_flag; // cant assemble without analysis
}
