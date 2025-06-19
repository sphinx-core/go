// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/core/stark/wrapper/stark.cpp
#include "stark.h"
#include <common/defs.hpp>
#include <protocols/protocol.hpp>
#include <jsoncpp/json.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <openssl/evp.h>

using namespace libstark;

class SphincsAIR : public AbstractAir {
public:
    SphincsAIR(const std::vector<uint8_t>& message,
               const std::vector<uint8_t>& pk_bytes,
               const std::vector<uint8_t>& merkle_root,
               const std::vector<uint8_t>& sig_bytes)
        : message_(message), pk_bytes_(pk_bytes),
          merkle_root_(merkle_root), sig_bytes_(sig_bytes) {}

    void UpdateInputs(const std::vector<uint8_t>& message,
                      const std::vector<uint8_t>& pk_bytes,
                      const std::vector<uint8_t>& merkle_root,
                      const std::vector<uint8_t>& sig_bytes) {
        message_ = message;
        pk_bytes_ = pk_bytes;
        merkle_root_ = merkle_root;
        sig_bytes_ = sig_bytes;
    }

    // Placeholder: Implement SPHINCS+ constraints
    void evaluateConstraints(Polynomial& res, const std::vector<FieldElement>& trace) const override {
        // SPHINCS+ SHAKE256-192f-robust:
        // - WOTS+ chain: SHAKE256 iterations
        // - Merkle paths: H(left, right) == parent
        // - Message hash: R || PKroot || M
    }

private:
    std::vector<uint8_t> message_;
    std::vector<uint8_t> pk_bytes_;
    std::vector<uint8_t> merkle_root_;
    std::vector<uint8_t> sig_bytes_;
};

void* init_prover(const char* air_config, const char* params_json) {
    try {
        Json::Value params;
        Json::Reader reader;
        if (!reader.parse(params_json, params)) return nullptr;
        // Placeholder: Configure libstark Prover
        return new Protocol::Prover(new SphincsAIR({}, {}, {}, {}));
    } catch (...) {
        return nullptr;
    }
}

int generate_proof(void* prover, const unsigned char* sig_bytes, size_t sig_len,
                   const unsigned char* message, size_t msg_len,
                   const unsigned char* pk_bytes, size_t pk_len,
                   const unsigned char* merkle_root, size_t root_len,
                   unsigned char* proof, size_t* proof_len) {
    try {
        Protocol::Prover* p = static_cast<Protocol::Prover*>(prover);
        SphincsAIR* air = dynamic_cast<SphincsAIR*>(p->getAir());
        air->UpdateInputs(
            std::vector<uint8_t>(message, message + msg_len),
            std::vector<uint8_t>(pk_bytes, pk_bytes + pk_len),
            std::vector<uint8_t>(merkle_root, merkle_root + root_len),
            std::vector<uint8_t>(sig_bytes, sig_bytes + sig_len)
        );
        // Placeholder: Generate proof
        std::vector<unsigned char> proof_bytes = p->prove();
        if (proof_bytes.size() <= *proof_len) {
            std::memcpy(proof, proof_bytes.data(), proof_bytes.size());
            *proof_len = proof_bytes.size();
            return 0;
        }
        return -1;
    } catch (...) {
        return -1;
    }
}

void* init_verifier(const char* air_config, const char* params_json) {
    try {
        Json::Value params;
        Json::Reader reader;
        if (!reader.parse(params_json, params)) return nullptr;
        // Placeholder: Configure libstark Verifier
        return new Protocol::Verifier(new SphincsAIR({}, {}, {}, {}));
    } catch (...) {
        return nullptr;
    }
}

int verify_proof(void* verifier, const unsigned char* proof, size_t proof_len,
                 const unsigned char* message, size_t msg_len,
                 const unsigned char* pk_bytes, size_t pk_len,
                 const unsigned char* merkle_root, size_t root_len) {
    try {
        Protocol::Verifier* v = static_cast<Protocol::Verifier*>(verifier);
        std::vector<unsigned char> proof_bytes(proof, proof + proof_len);
        std::vector<std::vector<unsigned char>> public_inputs = {
            std::vector<unsigned char>(message, message + msg_len),
            std::vector<unsigned char>(pk_bytes, pk_bytes + pk_len),
            std::vector<unsigned char>(merkle_root, merkle_root + root_len)
        };
        // Placeholder: Verify proof
        return v->verify(proof_bytes, public_inputs) ? 0 : -1;
    } catch (...) {
        return -1;
    }
}

void free_prover(void* prover) {
    delete static_cast<Protocol::Prover*>(prover);
}

void free_verifier(void* verifier) {
    delete static_cast<Protocol::Verifier*>(verifier);
}