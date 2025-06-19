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

// go/src/core/stark/wrapper/stark.h
#ifndef STARK_H
#define STARK_H

#ifdef __cplusplus
extern "C" {
#endif

void* init_prover(const char* air_config, const char* params_json);
int generate_proof(void* prover, const unsigned char* sig_bytes, size_t sig_len,
                  const unsigned char* message, size_t msg_len,
                  const unsigned char* pk_bytes, size_t pk_len,
                  const unsigned char* merkle_root, size_t root_len,
                  unsigned char* proof, size_t* proof_len);
void* init_verifier(const char* air_config, const char* params_json);
int verify_proof(void* verifier, const unsigned char* proof, size_t proof_len,
                const unsigned char* message, size_t msg_len,
                const unsigned char* pk_bytes, size_t pk_len,
                const unsigned char* merkle_root, size_t root_len);
void free_prover(void* prover);
void free_verifier(void* verifier);

#ifdef __cplusplus
}
#endif

#endif