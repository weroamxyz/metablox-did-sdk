#ifndef __MODELS_H__
#define __MODELS_H__
//#include
#include "conf/did_conf.h"
#include "did/did.h"
#include <stdlib.h>
#include <string.h>

// struct

typedef struct VCProof
{
    char type[32];
    char created[32];              // time
    char verification_method[128]; // https://
    char proof_purpose[32];
    char JWSSignature[129];
} VCProof;

typedef struct VPProof
{
    char type[128];
    char created[30];              // time
    char verification_method[256]; // https://
    char proof_purpose[128];
    char JWSSignature[129];
    char nonce[64];
} VPProof;

// vc
typedef struct verifiable_credential
{
    char **context;
    int count_context;
    char id[MAX_DID_STR_LEN];
    char **type;
    int count_type;
    char sub_type[128];
    char issuer[128];
    char issuance_data[128];
    char expiration_data[128];
    char description[128];
    char **CredentialSubject;
    int count_subject;
    VCProof vcProof;
    int revoked; // bool
} VC;

// vp
typedef struct verifiable_presentation
{
    char **context;
    int count_context;
    char **type;
    int count_type;
    VC **vc;
    int count_vc;
    char holder[256];
    VPProof vpProof;
} VP;

typedef void* vc_handle;
typedef void* vp_handle;
typedef void* did_handle;

#ifdef __cplusplus
extern "C"
{
#endif
    // void func
VC* create_vc_handle();
VP* create_vp_handle();
void vc_destroy(vc_handle vc);
void vp_destroy(vp_handle vp);

VC* new_vc(char **context, int count_text, char *id, char **type, int count_type, char *sub_type, char *issuer,
                 char *issuance_data, char *expiration_data, char *description, char **CredentialSubject, int count_subject, VCProof vcProof, int revoked);
VP* new_vp(char **context, int count_text, char **type, int count_type, VC **vc, int count_vc, char *holder, VPProof *vpProof);
VCProof *new_vc_proof(char *type, char *created, char *vm, char *proof_pursose);
VPProof *new_vp_proof(char *type, char *created, char *vm, char *proof_purpose);

void vc_signature(VC *vc, did_handle did, char *sig);
int  vc_verify(VC *vc, const did_meta_t* did, unsigned char* pubkey);
void vp_signature(VP *vp, did_handle did, char *sig);
int  vp_verify(VP* vp, const did_meta_t* holder_did, unsigned char* holder_pubkey, const did_meta_t** issuers_did, unsigned char** issuers_pubkey);

void convert_vc_to_bytes(VC *vc, char *out);
void convert_vp_to_bytes(VP *vc, char *out);

#ifdef __cplusplus
}
#endif

#endif /* __DID_H__ */
