#ifndef __DID_KEY_H__
#define __DID_KEY_H__ 

#include "unistd.h"
#ifdef TARGET_OS_IOS
#include "did_conf.h"
#include "key_generator.h"
#else
#include "conf/did_conf.h"
#include "did_key/key_generator.h"
#endif


typedef struct did_key_tag {
    unsigned char  id[MAX_DID_DOC_ELEMENT_ID_LEN];
    unsigned char  type[MAX_TYPE_LEN];
    unsigned char  controller[MAX_DID_STR_LEN];
    char  publicKeyAddress[MAX_KEY_ADDRESS_LEN];
    unsigned char  relationship[MAX_RELATIONSHIP_LEN];
} did_key_t;

#ifdef __cplusplus
extern "C" {
#endif

int key_sign_hash(key_pair_t* key, const char* algo, const char* hash, char *out, size_t out_len);
int key_verify_hash_with_address(const char* address, const char* algo, const char* hash, char* sign, size_t sign_len);

int key_verify_hash_with_pubkey(const char* pubkey, const char* address, const char* algo, const char* hash, char* sign, size_t sign_len);
int key_verify_hash_with_noaddress(const char* pubkey, const char* algo, const char* hash, char* sign, size_t sign_len);

int key_to_address(key_pair_t* key, const char* algo, char* address);
#ifdef __cplusplus
}
#endif

#endif /* __DID_KEY_H__ */
