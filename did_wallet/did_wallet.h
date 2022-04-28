#ifndef __DID_WALLET_H__
#define __DID_WALLET_H__

#include "did/did.h"

typedef void* wallet_handle;

#ifdef __cplusplus
extern "C" {
#endif 

wallet_handle   wallet_handle_create(const char* name, const char* path);
void            wallet_handle_destroy(wallet_handle handle);

int             wallet_store_did(wallet_handle wallet, did_handle did, const char* name, const char* password);
did_handle      wallet_load_did(wallet_handle wallet, const char* name, const char* password); 

int wallet_get_namelist(wallet_handle wallet, char *data);

#ifdef __cplusplus
}
#endif 

#endif 