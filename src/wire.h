// @file wire.h -- wire object for encrypted circuit evaluation object
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

#ifndef WIRE_H
#define WIRE_H
#include "binfhecontext.h"
#include <algorithm>
#include <deque>
#include <string>
#include <vector>

using NameList = std::vector<std::string>;
using CipherText = lbcrypto::LWECiphertext;

class Wire {
public:
  Wire();
  ~Wire();
  void setName(std::string n);
  std::string getName(void);
  void setValue(bool b);
  bool getValue(void);
  void setFanoutGates(NameList f);
  NameList getFanoutGates(void);
  unsigned int getNumberFanoutGates(void);
  void setCipherText(CipherText ct);
  CipherText getCipherText(void);

  void updateFanoutGates(std::string gateToRemove);

private:
  std::string name;     // note can be an integer
  NameList fanoutGates; // list of gates this wire fans out to
  bool value;
  CipherText ct; // used for encrypted value
};

using WireList = std::vector<Wire>;
using WireNameList = std::vector<std::string>;
using WireQueue = std::deque<Wire>;

#endif
