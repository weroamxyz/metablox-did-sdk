#ifndef __DID_H__
#define __DID_H__

#include "did_key/did_key.h"
#include "did_key/key_generator.h"

typedef struct did_meta_tag {
    char dummy;
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
int        did_verify(did_key_t* did_key, const char* msg, size_t msg_len, char* sign, size_t sign_len);

#ifdef __cplusplus
}
#endif
#endif /* __DID_H__ */