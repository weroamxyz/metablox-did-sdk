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

void wallet_change_name(wallet_handle wallet,const char* oldname,const char* newname);
void wallet_change_password(wallet_handle wallet,const char* name,const char* oldpassword,const char* newpassword);
#ifdef __cplusplus
}
#endif 

#endif 
