// @file gate.cpp -- encrypted circuit gate object
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
#include "gate.h"

#include <iostream>

GateEvalParams::GateEvalParams(void) {}

GateEvalParams::~GateEvalParams(void) {}

Gate::Gate(void) {}

Gate::~Gate(void) {}

void Gate::Reset(void) {}

void Gate::Evaluate(const GateEvalParams &gep) {
  OPENFHE_DEBUG_FLAG(false);
  OPENFHE_DEBUG("in evaluate for gate " << this->name);

  bool all_ready(true);

  auto plaintext_flag = gep.plaintext_flag;
  auto encrypted_flag = gep.encrypted_flag;
  auto verify_flag = gep.verify_flag;

  for (auto it : this->ready) {
    all_ready &= it;
  }
  if (!all_ready) {
    std::cerr << "error, executing gate " << this->name
              << " but inputs not ready!" << std::endl;
  }
  OPENFHE_DEBUGEXP(this->encin.size());
  OPENFHE_DEBUGEXP(plaintext_flag);
  OPENFHE_DEBUGEXP(encrypted_flag);
  if (encrypted_flag & dbg_flag) {
    OPENFHE_DEBUGEXP(this->encin[0]);
    lbcrypto::LWEPlaintext res;
    gep.cc.Decrypt(gep.sk, this->encin[0], &res);
    OPENFHE_DEBUGEXP(res);
    if (this->encin.size() > 1) {
      gep.cc.Decrypt(gep.sk, this->encin[1], &res);
      OPENFHE_DEBUGEXP(res);
    }
  }
  OPENFHE_DEBUGEXP(this->name);

  switch (this->op) {
  case (GateEnum::INPUT):
    std::cerr << "error executing input should not happen" << std::endl;
    break;
  case (GateEnum::OUTPUT):
    if (plaintext_flag) {
      plainout.resize(1);
      plainout[0] = this->plainin[0]; // copy input
    }
    if (encrypted_flag) {
      // lbcrypto::LWEPlaintext res;

      encout.resize(1);
      encout[0] = encin[0];
      if (verify_flag) {
        lbcrypto::LWEPlaintext res;
        gep.cc.Decrypt(gep.sk, this->encin[0], &res);
        unsigned int out = (unsigned int)res;
        if (out != plainout[0]) {
          std::cerr << "Bad OUTPUT fixing" << std::endl;
        }
      }
    }
    break;
  case (GateEnum::NOT):
    if (plaintext_flag) {
      plainout.resize(1);
      plainout[0] = !this->plainin[0];
    }
    if (encrypted_flag) {
      encout.resize(1);
      encout[0] = gep.cc.EvalNOT(this->encin[0]);
      if (verify_flag) {
        lbcrypto::LWEPlaintext res;
        gep.cc.Decrypt(gep.sk, encout[0], &res);
        if (res != plainout[0]) {
          std::cerr << "Bad NOT fixing" << std::endl;
          encout[0] = gep.cc.Encrypt(gep.sk, plainout[0]);
        }
      }
    }
    break;
  case (GateEnum::AND):
    if (plaintext_flag) {
      plainout.resize(1);
      plainout[0] = this->plainin[0] && this->plainin[1];
    }

    if (encrypted_flag) {
      encout.resize(1);
      try {
        encout[0] =
            gep.cc.EvalBinGate(lbcrypto::AND, this->encin[0], this->encin[1]);
      } catch (...) {
        std::cerr << "throw!! executing gate RETRY " << this->name << std::endl;
        lbcrypto::LWEPlaintext res;
        gep.cc.Decrypt(gep.sk, this->encin[0], &res);
        std::cerr << "in[0] " << res << std::endl;
        this->encin[0] = gep.cc.Encrypt(gep.sk, res);

        gep.cc.Decrypt(gep.sk, this->encin[1], &res);
        std::cerr << "in[1] " << res << std::endl;
        this->encin[1] = gep.cc.Encrypt(gep.sk, res);
        try {
          encout[0] =
              gep.cc.EvalBinGate(lbcrypto::AND, this->encin[0], this->encin[1]);
        } catch (...) {
          std::cerr << "FAILED rethrow!! executing gate RETRY " << this->name
                    << std::endl;
          exit(-1);
        }
      }
      if (verify_flag) {
        lbcrypto::LWEPlaintext res;
        gep.cc.Decrypt(gep.sk, encout[0], &res);
        if (res != plainout[0]) {
          std::cerr << "Bad AND fixing" << std::endl;
          encout[0] = gep.cc.Encrypt(gep.sk, plainout[0]);
        }
      }
    }
    break;
  case (GateEnum::OR):
    if (plaintext_flag) {
      plainout.resize(1);
      plainout[0] = this->plainin[0] || this->plainin[1];
    }

    if (encrypted_flag) {
      encout.resize(1);
      encout[0] =
          gep.cc.EvalBinGate(lbcrypto::OR, this->encin[0], this->encin[1]);

      if (verify_flag) {
        lbcrypto::LWEPlaintext res;
        gep.cc.Decrypt(gep.sk, encout[0], &res);
        if (res != plainout[0]) {
          std::cerr << "Bad OR fixing" << std::endl;
          encout[0] = gep.cc.Encrypt(gep.sk, plainout[0]);
        }
      }
    }

    break;
  case (GateEnum::XOR):
    if (plaintext_flag) {
      plainout.resize(1);
      plainout[0] = this->plainin[0] ^ this->plainin[1];
      OPENFHE_DEBUGEXP(plainout[0]);
    }

    if (encrypted_flag) {
      encout.resize(1);
#if 1 // current XOR has a higher failure rate, replace with equivalent gates
	  auto foo = gep.cc.EvalBinGate(lbcrypto::XOR, this->encin[0], this->encin[1]);
#else
	  auto foo = gep.cc.EvalBinGate(lbcrypto::XOR_FAST, this->encin[0], this->encin[1]);    
#endif
      encout[0] = foo;
      OPENFHE_DEBUGEXP(encout[0]);
      if (verify_flag) {
        lbcrypto::LWEPlaintext res;
        gep.cc.Decrypt(gep.sk, encout[0], &res);
        if (res != plainout[0]) {
          std::cerr << "Bad XOR fixing" << std::endl;
          encout[0] = gep.cc.Encrypt(gep.sk, plainout[0]);
        }
      }
    }

    break;
  case (GateEnum::DFF):
    std::cerr << "remember to write DFF" << std::endl;
    break;
  case (GateEnum::LUT3):
    std::cerr << "remember to write LUT3" << std::endl;
    break;
  case (GateEnum::LUT4):
    std::cerr << "remember to write LUT4" << std::endl;
    break;
  default:
    std::cerr << "bad gate eval" << std::endl;
  }
}
