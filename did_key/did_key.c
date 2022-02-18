#include "did_key.h"
#include "stdlib.h"
#include "secp256k1/seck256k1_key.h"

int key_sign(key_pair_t* key, const char* algo, const char* msg, size_t msg_len, char *out, size_t out_len) 
{
    if (strcmp("algo", "secp256k1") == 0) {
        
    } else {
        return 0;
    }
}

int key_verify(key_pair_t* key, const char* algo, const char* msg, size_t msg_len, char* sign, size_t sign_len)
 {

 }