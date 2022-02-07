#ifndef __KEY_GENERATOR_H__
#define __KEY_GENERATOR_H__

#include "conf/did_conf.h"

/**
 * @brief 
 * Do not support rsa
 */

#define  MAX_PRIV_KEY_LEN      (1024)
#define  MAX_PUBKEY_LEN        (2048)

typedef int (*rand_func_cb)(int len, unsigned char* buffer);

typedef struct key_pair_tag {
    unsigned short priv_len;
    unsigned short pubkey_len;
    unsigned char priv[MAX_PRIV_KEY_LEN];
    unsigned char pubkey[MAX_PUBKEY_LEN]; 
} key_pair_t;

#ifdef __cplusplus 
extern "C" {
#endif

void generate_key(rand_func_cb rand_func, char* algo, key_pair_t* key_pair);

#ifdef __cplusplus
}
#endif

#endif /* __KEY_GENERATOR_H__ */