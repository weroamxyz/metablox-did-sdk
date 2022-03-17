#ifndef __DID_H__
#define __DID_H__

#include "unistd.h"
#include "did_key.h"
#include "key_generator.h"

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

typedef void*  did_handle;

#ifdef __cplusplus
extern "C" {
#endif

did_handle did_create(const char* algo, rand_func_cb rand_func);
void       did_destroy(did_handle handle);
int        did_serialize(did_handle handle, char* buffer, size_t buff_len);
did_handle did_deserialize(const char* buffer);
int        did_sign(did_handle handle, const char* msg, size_t msg_len, char *out, size_t out_len);
int        did_verify(did_key_t* did_key, const char* msg, size_t msg_len, const char* sign, size_t sign_len);

did_meta_t*  did_to_did_meta(did_handle handle);
void         did_meta_destroy(did_meta_t* meta);  

#ifdef __cplusplus
}
#endif
#endif /* __DID_H__ */
