#ifndef __DID_KEY_H__
#define __DID_KEY_H__ 

#include "conf/did_conf.h"
#include "did_key/key_generator.h"

typedef struct did_key_tag {
    unsigned char  id[MAX_DID_DOC_ELEMENT_ID_LEN];
    unsigned char  type[MAX_TYPE_LEN];
    unsigned char  controller[MAX_DID_STR_LEN];
    unsigned char  publicKeyBase58[MAX_KEY_PUBKEY_BASE58_LEN];
    unsigned char  relationship[MAX_RELATIONSHIP_LEN];
} did_key_t;

int key_sign(key_pair_t* key, const char* algo, const char* msg, size_t msg_len, char *out, size_t out_len);
int key_verify(key_pair_t* key, const char* algo, const char* msg, size_t msg_len, char* sign, size_t sign_len);

#endif /* __DID_KEY_H__ */