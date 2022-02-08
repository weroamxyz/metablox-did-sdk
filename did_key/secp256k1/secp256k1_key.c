#include "secp256k1/include/secp256k1.h"
#include "../key_generator.h"
#include "stdlib.h"

int generate_secp256k1_keypair(rand_func_cb rand_func, key_pair_t* key_pair) 
{
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL) {
        return -1;
    }
    
    unsigned char key[32] = {0};

    while (1) {
        rand_func(32, key);
        
        if (secp256k1_ec_seckey_verify(ctx, key) == 1) 
        {
            break;
        }
    }

    secp256k1_pubkey pubkey = {0};
    secp256k1_ec_pubkey_create(ctx, &pubkey, key);
    
    key_pair->priv_len = 32;
    key_pair->pubkey = 64;
    memcpy(key_pair->priv, key, 32);
    memcpy(key_pair->pubkey, pubkey.data, 64);

    secp256k1_context_destroy(ctx);
    return 0;
}

