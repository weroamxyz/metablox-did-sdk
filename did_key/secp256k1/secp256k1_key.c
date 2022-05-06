#include "secp256k1_key.h"
#include "secp256k1/include/secp256k1_recovery.h"
#include "../key_generator.h"
#include "stdlib.h"
#include "string.h"
#include "common/sha256.h"
#include <stdio.h>
#include "keccak256/keccak256.h"

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
    int d = secp256k1_ec_pubkey_create(ctx, &pubkey, key);
    
    key_pair->priv_len = 32;
    key_pair->pubkey_len = 64;
    memcpy(key_pair->priv, key, 32);
    memcpy(key_pair->pubkey, pubkey.data, 64);

    secp256k1_context_destroy(ctx);
    return 0;
}

int import_secp256k1_keypair(const char* priv_key, key_pair_t* key_pair)
{
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL) {
        return -1;
    }
    
    if (secp256k1_ec_seckey_verify(ctx, priv_key) == 0)
    {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    secp256k1_pubkey pubkey = {0};
    int d = secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key);
    
    key_pair->priv_len = 32;
    key_pair->pubkey_len = 64;
    memcpy(key_pair->priv, priv_key, 32);
    memcpy(key_pair->pubkey, pubkey.data, 64);

    secp256k1_context_destroy(ctx);
    return 0;
}

int secp256k1_sign(const char*priv_key, const char* msg, size_t msg_len, char *out, size_t out_len) 
{
    if (out == NULL) 
    {
        return 65;
    }
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL) {
        return -1;
    }

    char hash[32] = {0};
    secp256k1_ecdsa_recoverable_signature signature = {0};
    SHA256_CTX sha256_ctx = {0};

    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, msg, msg_len);
    sha256_final(&sha256_ctx, hash);
  
    secp256k1_ecdsa_sign_recoverable(ctx, &signature, hash, priv_key, secp256k1_nonce_function_rfc6979, NULL);
    
    int copy_len = 65;
    if (copy_len < out_len)
    {
        copy_len = out_len;
    }
    memcpy(out, signature.data, copy_len);
    secp256k1_context_destroy(ctx);

    return copy_len;
}

int secp256k1_verify(const char* public_key, const char* msg, size_t msg_len, const char* signature)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL){
        return -1;
    }

    secp256k1_ecdsa_recoverable_signature sig;
    memcpy(sig.data, signature, 65);

    secp256k1_pubkey pubkey;

    char hash[32] = {0};
    SHA256_CTX sha256_ctx = {0};

    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, msg, msg_len);
    sha256_final(&sha256_ctx, hash);

    int result_rec = secp256k1_ecdsa_recover(ctx, &pubkey, &sig, hash);
    if (result_rec == 0){
        secp256k1_context_destroy(ctx);
        return -1;
    }

    char result[32] = {0};
    SHA3_CTX sha3_ctx;
    keccak_init(&sha3_ctx);
    keccak_update(&sha3_ctx, pubkey.data, 64);
    keccak_final(&sha3_ctx, result);

    char pHex[64] = {0};
    int i = 0;
    for (i = 0; i < 32; i++){
        char strTemp[3] = {0};
        sprintf(strTemp, "%02x", (unsigned char)result[i]);
        strcat(pHex, strTemp);
    }

    char ret[42];
    ret[0] = '0';
    ret[1] = 'x';
    memcpy(ret + 2, pHex + 24, 40);

    secp256k1_context_destroy(ctx);

    result_rec = memcmp(public_key, ret, 42);

    if (result_rec == 0)
        return 0;
    return -1;
}