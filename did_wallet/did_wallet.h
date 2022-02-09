#ifndef __DID_WALLET_H__
#define __DID_WALLET_H__

typedef void* wallet_handle;

#ifdef __cplusplus
extern "C" {
#endif 

wallet_handle   wallet_handle_create();
void            wallet_handle_destroy(wallet_handle handle);

//void 

#ifdef __cplusplus
}
#endif 

#endif 