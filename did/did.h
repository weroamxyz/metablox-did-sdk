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
int        did_serialize(did_handle handle, char* buffer, int buff_len);
did_handle did_deserialize(const char* buffer);
#ifdef __cplusplus
}
#endif
#endif /* __DID_H__ */