#ifndef __SECP256K1_KEY_H__
#define __SECP256K1_KEY_H__

#include "../key_generator.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int generate_secp256k1_keypair(rand_func_cb rand_func, key_pair_t* key_pair);
int secp256k1_sign(const char*priv_key, const char* msg, size_t msg_len, char *out, size_t out_len);
int secp256k1_verify(const char* public_key, const char* msg, size_t msg_len, const char* signature);

#ifdef __cplusplus
}
#endif
#endif /* __SECP256K1_KEY_H__ */
