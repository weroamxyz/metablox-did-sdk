#ifndef __DID_REGISTER_H__
#define __DID_REGISTER_H__

#include "did/did.h"

typedef void*  register_handle;


#ifdef __cplusplus
extern "C" {
#endif

register_handle register_create(const char* url);
void            register_destroy(register_handle handle);

int  register_submit(register_handle handle, did_handle did);

#ifdef __cplusplus
}
#endif
#endif /* __DID_REGISTER_H__ */