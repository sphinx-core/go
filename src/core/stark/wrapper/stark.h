#ifndef WRAPPER_H
#define WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

// Initialize STARK prover
void* init_prover(const char* air_config, const char* params_json);

// Generate proof
int generate_proof(void* prover, const unsigned char* sig_bytes, size_t sig_len,
                  const unsigned char* message, size_t msg_len,
                  const unsigned char* pk_bytes, size_t pk_len,
                  const unsigned char* merkle_root, size_t root_len,
                  unsigned char* proof, size_t* proof_len);

// Initialize STARK verifier
void* init_verifier(const char* air_config, const char* params_json);

// Verify proof
int verify_proof(void* verifier, const unsigned char* proof, size_t proof_len,
                const unsigned char* message, size_t msg_len,
                const unsigned char* pk_bytes, size_t pk_len,
                const unsigned char* merkle_root, size_t root_len);

// Free resources
void free_prover(void* prover);
void free_verifier(void* verifier);

#ifdef __cplusplus
}
#endif

#endif