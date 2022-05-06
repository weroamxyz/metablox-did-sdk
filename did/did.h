#ifndef __DID_H__
#define __DID_H__

#include "unistd.h"
#include "did_key/did_key.h"
#include "did_key/key_generator.h"
#include "keccak256/keccak256.h"

typedef struct did_service_tag {
    char   id[MAX_ID_LEN];
    char   type[MAX_TYPE_LEN];
    char   endpoint[MAX_URL_LEN];
} did_service_t;

typedef struct did_meta_tag {
    char      did[MAX_DID_STR_LEN];
    char      controller[MAX_DID_STR_LEN];
    did_key_t* did_keys;
    did_service_t* did_services;
} did_meta_t;

typedef struct priv_key_memo_tag {
    char algo[MAX_ALGO_LEN];
    int  priv_key_len;
    char priv_key[MAX_PRIV_KEY_LEN];
} priv_key_memo_t;

typedef void*  did_handle;

#ifdef __cplusplus
extern "C" {
#endif

did_handle did_create(const char* algo, rand_func_cb rand_func);
void       did_destroy(did_handle handle);
int        did_serialize(did_handle handle, char* buffer, size_t buff_len);
did_handle did_deserialize(const char* buffer);
int        did_sign(did_handle handle, const char* msg, size_t msg_len, char *out, size_t out_len);
int        did_verify(did_key_t* did_key, const char* msg, size_t msg_len, char* sign, size_t sign_len);

did_meta_t*  did_to_did_meta(did_handle handle);
void         did_meta_destroy(did_meta_t* meta);  

//2022.4.16     meiqiu
int         did_export_prikey(did_handle handle,char *out);
did_handle  did_import_privkey(const char *priv_key);
char        HexCharToBinChar(char c);



//2022.5.2
char* getDIDstring(did_handle* did_handl);
int did_export_pubkey(did_handle did, char *eth_address);


#ifdef __cplusplus
}
#endif
#endif /* __DID_H__ */
