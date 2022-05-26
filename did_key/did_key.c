#include "did_key.h"
#include "stdlib.h"
#include "string.h"
#include "stddef.h"
#include "secp256k1/secp256k1_key.h"

int key_sign_hash(key_pair_t* key, const char* algo, const char* hash, char *out, size_t out_len)
{
    if (strcmp(algo, "secp256k1") == 0) {
        return secp256k1_sign_hash(key->priv, hash, out, out_len);
    } else {
        return -1;
    }
}

int key_verify_hash_with_address(const char* address, const char* algo, const char* hash, char* sign, size_t sign_len)
{
    if (strcmp(algo, "secp256k1") == 0) {
        return secp256k1_verify_hash(address, hash, sign);
    } else {
        return -1;
    }
}

int key_verify_hash_with_pubkey(const char* pubkey, const char* address, const char* algo, const char* hash, char* sign, size_t sign_len)
{
    if (strcmp(algo, "secp256k1") == 0) {
        return secp256k1_verify_hash_with_pubkey(pubkey, address, hash, sign);
    } else {
        return -1;
    }
}

int key_verify_hash_with_noaddress(const char* pubkey, const char* algo, const char* hash, char* sign, size_t sign_len)
{
    if (strcmp(algo, "secp256k1") == 0) {
        return secp256k1_verify_hash_with_pubkey_noaddress(pubkey, hash, sign);
    } else {
        return -1;
    }
}

int key_to_address(key_pair_t* key, const char* algo, char* address)
{
    if (strcmp(algo, "secp256k1") == 0) {
        return secp256k1_key_to_address(key->pubkey, address);
    } else {
        return 0;
    }
}

