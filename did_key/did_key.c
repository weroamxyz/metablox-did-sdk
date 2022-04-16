#include "did_key.h"
#include "stdlib.h"
#include "string.h"
#include "stddef.h"
#include "secp256k1/secp256k1_key.h"

int key_sign(key_pair_t* key, const char* algo, const char* msg, size_t msg_len, char *out, size_t out_len) 
{
    if (strcmp(algo, "secp256k1") == 0) {
        return secp256k1_sign(key->priv, msg, msg_len, out, out_len);   
    } else {
        return 0;
    }
}

int key_verify(key_pair_t* key, const char* algo, const char* msg, size_t msg_len, char* sign, size_t sign_len)
{
    if (strcmp(algo, "secp256k1") == 0) {
        return secp256k1_verify(key->pubkey, msg, msg_len, sign);   
    } else {
        return 0;
    }
}
