#ifndef __MODELS_H__
#define __MODELS_H__
//#include

#ifdef TARGET_OS_IOS
#include "did_conf.h"
#include "did.h"
#else
#include "conf/did_conf.h"
#include "did/did.h"
#endif

#include <stdlib.h>
#include <string.h>

// struct
typedef struct subject
{
    char ID[128];
    char GivenName[64];
    char FamilyName[64];
    char Gender[64];
    char BirthCountry[64];
    char BirthDate[64];
} subject_info;

typedef struct wifi_access
{
    char CredentialID[128];
    char ID[128];
    char Type[64];
} wifi_access_info;

typedef struct mining_license
{
    char CredentialID[128];
    char ID[128];
    char Name[64];
    char Model[64];
    char Serial[64];
} mining_license_info;

typedef struct staking_vc
{
    char CredentialID[128];
    char ID[128];
} staking_vc_info;

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
    void *CredentialSubject;
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
typedef void *did_handle;

#ifdef __cplusplus
extern "C"
{
#endif
    // void func
    wifi_access_info *cretae_wifi_access(const char *credential_id, const char *id, const char *type);
    mining_license_info *create_mining_license(const char *credential_id, const char *id, const char *name, const char *model, const char *serial);
    staking_vc_info *create_staking_vc(const char *credential_id, const char *id);
    subject_info *create_subject(const char *id, const char *given_name, const char *family_name, const char *gender, const char *birth_country, const char *birth_date);

    VC *create_vc_handle();
    VP *create_vp_handle();
    void vc_destroy(vc_handle vc);
    void vp_destroy(vp_handle vp);

    VC *new_vc(char *const *context, const int count_text, const char *id, char *const *, const int count_type, const char *issuer, const char *issuance_data, const char *expiration_data, const char *description, void *CredentialSubject, const int count_subject, const VCProof *vcProof, const int revoked);
    VP *new_vp(char *const *context, const int count_text, char *const *type, const int count_type, VC *const *vc, const int count_vc, const char *holder, const VPProof *vpProof);
    VCProof *new_vc_proof(const char *type, const char *created, const char *vm, const char *proof_pursose, const char *jws, const unsigned char *pub_key);
    VPProof *new_vp_proof(const char *type, const char *created, const char *vm, const char *proof_purpose, const char *jws, const char *nonce, const unsigned char *pub_key);

    void vc_signature(VC *vc, did_handle did, char *sig);
    int vc_verify(VC *vc);
    void vp_signature(VP *vp, did_handle did, char *sig);
    int vp_verify(VP *vp);

    void convert_vc_to_bytes(const VC *vc, char *out, int *out_len);
    void convert_vp_to_bytes(const VP *vc, char *out, int *out_len);

    void vc_to_json(VC *vc, char *out);
    VC* json_to_vc(const char* buffer);

#ifdef __cplusplus
}
#endif

#endif /* __DID_H__ */