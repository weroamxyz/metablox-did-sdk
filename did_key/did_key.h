#ifndef __DID_KEY_H__
#define __DID_KEY_H__ 

#include "conf/did_conf.h"

typedef struct did_key_tag {
    unsigned char  id[MAX_DID_DOC_ELEMENT_ID_LEN];
    unsigned char  type[MAX_TYPE_LEN];
    unsigned char  controller[MAX_DID_STR_LEN];
    unsigned char  publicKeyHex[MAX_KEY_PUBKEY_HEX_LEN];
    unsigned char  relationship[MAX_RELATIONSHIP_LEN];
} did_key_t;


#endif /* __DID_KEY_H__ */