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
    char public_key[65];
} VCProof;

typedef struct VPProof
{
    char type[128];
    char created[30];              // time
    char verification_method[256]; // https://
    char proof_purpose[128];
    char JWSSignature[129];
    char nonce[64];
    char public_key[65];
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

<<<<<<< HEAD
VC* new_vc(char* const*context,const int count_text,const char *id,char* const*,const int count_type,const char *sub_type,const char *issuer,const char *issuance_data,const char *expiration_data,const char *description,char* const*CredentialSubject,const int count_subject,const VCProof *vcProof,const int revoked);
VP* new_vp(char* const*context,const int count_text,char* const*type,const int count_type,VC* const*vc,const int count_vc,const char *holder,const VPProof *vpProof);
VCProof *new_vc_proof(const char *type, const char *created, const char *vm, const char *proof_pursose, const char *jws, const unsigned char*pub_key);
VPProof *new_vp_proof(const char *type, const char *created, const char *vm, const char *proof_purpose, const char *jws, const char *nonce, const unsigned char*pub_key);
=======
VC* new_vc(char * const *context,const int count_text,const char *id, char * const*type,const int count_type,const char *sub_type,const char *issuer,const char *issuance_data,const char *expiration_data,const char *description, char * const*CredentialSubject,const int count_subject,const VCProof vcProof,const int revoked);
VP* new_vp(char * const *context,const int count_text, char * const *type, const int count_type, VC * const *vc,const int count_vc,const char *holder,const VPProof *vpProof);
VCProof *new_vc_proof(const char *type, const char *created, const char *vm, const char *proof_pursose, const char *jws, const char *public_key);
VPProof *new_vp_proof(const char *type, const char *created, const char *vm, const char *proof_purpose, const char *jws, const char *nonce, const char *public_key);
>>>>>>> 947f83739f58d554375130c33d6fdbbc1748a44c

void vc_signature(VC *vc, did_handle did, char *sig);
int  vc_verify(VC *vc);
void vp_signature(VP *vp, did_handle did, char *sig);
int  vp_verify(VP* vp);

void convert_vc_to_bytes(const VC *vc, char *out, int *out_len);
void convert_vp_to_bytes(const VP *vc, char *out, int *out_len);

#ifdef __cplusplus
}
#endif

#endif /* __DID_H__ */
