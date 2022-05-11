#ifndef __MODELS_H__
#define __MODELS_H__
//#include
#include "conf/did_conf.h"
#include <stdlib.h>
#include <string.h>

// struct

typedef struct VCProof
{
    char type[32];
    char created[32];              // time
    char verification_method[128]; // https://
    char proof_purpose[32];
    char JWSSignature[64];
} VCProof;

typedef struct VPProof
{
    char type[128];
    char created[30];              // time
    char verification_method[256]; // https://
    char proof_purpose[128];
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

typedef void *vc_handle;
typedef void *vp_handle;
typedef void* did_handle;

#ifdef __cplusplus
extern "C"
{
#endif
    // void func
    vc_handle create_vc_handle();
    vp_handle create_vp_handle();
    void vc_destroy(vc_handle vc);
    void vp_destroy(vp_handle vp);

    vc_handle new_vc(char **context, int count_text, char *id, char **type, int count_type, char *sub_type, char *issuer,
                     char *issuance_data, char *expiration_data, char *description, char **CredentialSubject, int count_subject, VCProof vcProof, int revoked);
    vp_handle new_vp(char **context, int count_text, char **type, int count_type, VC **vc, int count_vc, char *holder, VPProof *vpProof);
    VCProof *new_vc_proof(char *type, char *created, char *vm, char *proof_pursose);
    VPProof *new_vp_proof(char *type, char *created, char *vm, char *proof_purpose);


    void ConvertVCToBytes(VC *vc, char *out);
    void ConvertVPToBytes(VP *vc, char *out);
    int CreatJWSSignature(VC *vc, char *sig);
    int CreatNonce(VP *vp, char *sig);

#ifdef __cplusplus
}
#endif

#endif /* __DID_H__ */
