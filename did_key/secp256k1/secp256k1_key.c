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
    memcpy(key_pair->priv, key, 32);
    
    key_pair->pubkey_len = 65;
    size_t outputlen = 65;
    secp256k1_ec_pubkey_serialize(ctx, key_pair->pubkey, &outputlen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    key_pair->pubkey_len = outputlen;

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

    key_pair->priv_len = 32;
    memcpy(key_pair->priv, priv_key, 32);
    
    secp256k1_pubkey pubkey = {0};
    int d = secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key);
    key_pair->pubkey_len = 65;
    size_t outputlen = 65;
    secp256k1_ec_pubkey_serialize(ctx, key_pair->pubkey, &outputlen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    key_pair->pubkey_len = outputlen;


    secp256k1_context_destroy(ctx);
    return 0;
}

int secp256k1_sign_hash(const char*priv_key, const char* hash, char *out, size_t out_len)
{
    if (out == NULL) 
    {
        return 65;
    }
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL) {
        return -1;
    }

    secp256k1_ecdsa_recoverable_signature signature = {0};
    secp256k1_ecdsa_sign_recoverable(ctx, &signature, hash, priv_key, secp256k1_nonce_function_rfc6979, NULL);
    
    int recv_id = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, out, &recv_id, &signature);
    out[64] = (char)recv_id;
    
    secp256k1_context_destroy(ctx);
    return 65;
}

int secp256k1_verify_hash(const char* input_address, const char* hash, const char* signature)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL){
        return -1;
    }
    
    int recv_id = signature[64];
    
    secp256k1_ecdsa_recoverable_signature sig;
    secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, signature, recv_id);

    secp256k1_pubkey pubkey;

    int result_rec = secp256k1_ecdsa_recover(ctx, &pubkey, &sig, hash);
    if (result_rec == 0){
        secp256k1_context_destroy(ctx);
        return -1;
    }
    char output[65] = {0};
    size_t outputlen = 65;
    secp256k1_ec_pubkey_serialize(ctx, output, &outputlen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    char address[42] = {0};
    secp256k1_key_to_address(output, address);
    
    secp256k1_context_destroy(ctx);

    result_rec = memcmp(input_address, address, 42);

    if (result_rec == 0)
        return 0;
    return -1;
}

int secp256k1_verify_hash_with_pubkey(const char* pubkey, const char* address, const char* hash, const char* signature)
{
    char pub_address[MAX_KEY_ADDRESS_LEN] = {0};
    secp256k1_key_to_address(pubkey, pub_address);
    
    if (memcmp(pub_address, address, 42) != 0) {
        return -1;
    }
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL){
        return -1;
    }
        
    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature);
    
    secp256k1_pubkey pubkey_r;
    int result_rec = secp256k1_ec_pubkey_parse(ctx, &pubkey_r, pubkey, 65);
    if (result_rec == 0){
        secp256k1_context_destroy(ctx);
        return -1;
    }

    result_rec = secp256k1_ecdsa_verify(ctx, &sig, hash, &pubkey_r);
    secp256k1_context_destroy(ctx);
    if (result_rec == 1)
        return 0;
    return -1;
}

int secp256k1_verify_hash_with_pubkey_noaddress(const char* pubkey, const char* hash, const char* signature)
{
//    char pub_address[MAX_KEY_ADDRESS_LEN] = {0};
//    secp256k1_key_to_address(pubkey, pub_address);
//
//    if (memcmp(pub_address, address, 42) != 0) {
//        return -1;
//    }
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL){
        return -1;
    }
        
    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature);
    
    secp256k1_pubkey pubkey_r;
    int result_rec = secp256k1_ec_pubkey_parse(ctx, &pubkey_r, pubkey, 65);
    if (result_rec == 0){
        secp256k1_context_destroy(ctx);
        return -1;
    }

    result_rec = secp256k1_ecdsa_verify(ctx, &sig, hash, &pubkey_r);
    secp256k1_context_destroy(ctx);
    if (result_rec == 1)
        return 0;
    return -1;
}

int secp256k1_key_to_address(const char* public_key, char* address)
{
    char result[32] = {0};
    SHA3_CTX sha3_ctx;
    keccak_init(&sha3_ctx);
    keccak_update(&sha3_ctx, public_key + 1, 64);
    keccak_final(&sha3_ctx, result);
    
    strcpy(address, "0x");
    for (int i = 0; i < 20; i++){
        sprintf(address + i * 2 + 2, "%02x", (unsigned char)result[i + 12]);
    }
    
    unsigned char check_hash[32] = {0};
    keccak_init(&sha3_ctx);
    keccak_update(&sha3_ctx, address + 2, 40);
    keccak_final(&sha3_ctx, check_hash);
    
    for (int i = 2; i < 42; i++)
    {
        unsigned char hash_byte = check_hash[(i - 2) / 2];
        if ((i % 2) == 0)
        {
            hash_byte = hash_byte >> 4;
        } else {
            hash_byte = hash_byte & 0xF;
        }
        
        if (address[i] > '9' && hash_byte > 7) {
            address[i] = address[i] - 32;
        }
    }
    
    return 42;
}
