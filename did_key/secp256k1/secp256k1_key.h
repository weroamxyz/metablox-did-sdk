#ifndef __SECP256K1_KEY_H__
#define __SECP256K1_KEY_H__

#include "../key_generator.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int generate_secp256k1_keypair(rand_func_cb rand_func, key_pair_t* key_pair);
int import_secp256k1_keypair(const char* priv_key, key_pair_t* key_pair);
int secp256k1_sign_hash(const char*priv_key, const char* hash, char *out, size_t out_len);
int secp256k1_verify_hash(const char* input_address, const char* hash, const char* signature);

int secp256k1_verify_hash_with_pubkey(const char* pubkey, const char* address, const char* hash, const char* signature);
int secp256k1_verify_hash_with_pubkey_noaddress(const char* pubkey, const char* hash, const char* signature);

int secp256k1_key_to_address(const char* public_key, char* address);

#ifdef __cplusplus
}
#endif
#endif /* __SECP256K1_KEY_H__ */
