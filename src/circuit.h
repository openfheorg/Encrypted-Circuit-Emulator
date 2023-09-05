// @file circuit.h -- encrypted circuit evaluation object
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
#ifndef SRC_CIRCUIT_EVAL_H_
#define SRC_CIRCUIT_EVAL_H_

#include <algorithm>
#include <deque>
#include <string>
#include <vector>
#include <omp.h>
#include "gate.h"
#include "wire.h"

using GateNameList = std::vector<std::string>;
using GateList = std::vector<Gate>;
using GateQueue = std::deque<Gate>;

using Inputs = std::vector<std::vector<unsigned int>>;
using Outputs = std::vector<std::vector<unsigned int>>;
using NetList = std::unordered_map<std::string, GateNameList>;

class Circuit {
public:
  Circuit(lbcrypto::BINFHE_PARAMSET set, lbcrypto::BINFHE_METHOD method);
  ~Circuit();
  bool ReadFile(std::string cktName);
  void Reset(void);
  void SetInput(Inputs input, bool verbose = false);
  std::string Evaluate(void);
  void setPlaintext(bool);
  bool getPlaintext(void);
  void setEncrypted(bool);
  bool getEncrypted(void);
  void setVerify(bool);
  bool getVerify(void);
  Outputs Clock(void);

  void dumpNetList(void);
  void dumpGates(void);
  void dumpGateCount(void);

private:
  lbcrypto::BinFHEContext cc;
  lbcrypto::LWEPrivateKey sk;

  bool plaintext_flag; // if true perform plaintext logic
  bool encrypted_flag; // if true perform encrypted logic
  bool verify_flag;    // if true verify plaintext vs encrypted logic

  NetList nl; // full net list of the ckt (all wires and fanout gates)

  WireNameList waitingWireNames;
  WireQueue activeWires;

  GateList inputGates; // input gates in ckt
  GateList allGates;   // all other gates in ckt

  GateQueue readyGates;
  GateQueue waitingGates;
  GateQueue executingGates;
  GateQueue examinedGates;
  GateQueue doneGates;
  bool done;

  bool _parse_input(Inputs, std::string, std::string);
  void _parse_output(std::string, std::string, bool);
  void _CircuitManager(void);
  void _ExecuteGates(void);

  GateEvalParams gep;

  unsigned int n_outputs;
  std::vector<unsigned int> n_output_bits;
  Outputs circuitOut;

  unsigned int n_input_gates;
  unsigned int n_output_gates;
  unsigned int n_and_gates;
  unsigned int n_or_gates;
  unsigned int n_xor_gates;
  unsigned int n_not_gates;
};

#endif
