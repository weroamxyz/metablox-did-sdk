#ifndef __KEY_GENERATOR_H__
#define __KEY_GENERATOR_H__

#ifdef TARGET_OS_IOS
#include "did_conf.h"
#else
#include "conf/did_conf.h"
#endif

/**
 * @brief 
 * Do not support rsa
 */

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

void generate_key_pair(rand_func_cb rand_func, const char* algo, key_pair_t* key_pair);

void import_key_pair(const char* algo, int priv_ken, const char* priv_key, key_pair_t* key_pair);

#ifdef __cplusplus
}
#endif

#endif /* __KEY_GENERATOR_H__ */
