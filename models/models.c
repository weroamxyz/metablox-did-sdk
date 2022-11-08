#include "models/models.h"
#include "stdlib.h"
#include "string.h"
#include "stddef.h"
#include "common/sha256.h"
#include "common/base64.h"
#include "common/base58.h"
#include "stdio.h"

static void jws_signature(const unsigned char *hash, did_handle did, char *sig);

VC *create_vc_handle()
{
    VC *vc_handl = (VC *)malloc(sizeof(VC));
    if (vc_handl == NULL)
        return NULL;
    memset(vc_handl, 0, sizeof(VC));
    return vc_handl;
}

VP *create_vp_handle()
{
    VP *vp_hand = (VP *)malloc(sizeof(VP));
    if (vp_hand == NULL)
        return NULL;
    memset(vp_hand, 0, sizeof(VP));
    return vp_hand;
}

void vc_destroy(vc_handle vc)
{
    VC *vc_handl = (VC *)vc;
    if (vc_handl == NULL)
        return;

    int i = 0;
    if (vc_handl->context != NULL && vc_handl->count_context >= 0)
    {
        for (i = 0; i < vc_handl->count_context; i++)
        {
            if (vc_handl->context[i] != NULL)
            free(vc_handl->context[i]);
        }
    }
    free(vc_handl->context);
    if (vc_handl->type != NULL && vc_handl->count_type >= 0)
    {
        for (i = 0; i < vc_handl->count_type; i++)
        {
            if (vc_handl->type[i] != NULL)
            free(vc_handl->type[i]);
        }
    }
    free(vc_handl->type);
    if (vc_handl->CredentialSubject != NULL && vc_handl->count_subject >= 0)
    {
        for (i = 0; i < vc_handl->count_subject; i++)
        {
            if (vc_handl->CredentialSubject[i] != NULL)
            free(vc_handl->CredentialSubject[i]);
        }
    }
    free(vc_handl->CredentialSubject);
    free(vc_handl);
}

void vp_destroy(vp_handle vp)
{
    VP *vp_hand = (VP *)vp;
    if (vp_hand == NULL)
        return;

    int i = 0;
    if (vp_hand->context != NULL && vp_hand->count_context >= 0)
    {
        for (i = 0; i < vp_hand->count_context; i++)
        {
            if (vp_hand->context[i] != NULL)
            free(vp_hand->context[i]);
        }
    }
    free(vp_hand->context);
    if (vp_hand->type != NULL && vp_hand->count_type >= 0)
    {
        for (i = 0; i < vp_hand->count_type; i++)
        {
            if (vp_hand->type[i] != NULL)
            free(vp_hand->type[i]);
        }
    }
   free(vp_hand->type);
   free(vp_hand);
}

VC *new_vc(char *const*context,const int count_text,const char *id,char *const*type,const int count_type,const char *sub_type,const char *issuer,const char *issuance_data,const char *expiration_data,const char *description,char *const*CredentialSubject,const int count_subject,const VCProof *vcProof,const int revoked)
{
    VC *vc_handl = create_vc_handle();
    int i = 0;
    vc_handl->count_context = count_text;
    vc_handl->context = (char **)malloc(sizeof(char *) * vc_handl->count_context);
    memset(vc_handl->context, 0, sizeof(sizeof(char *) * vc_handl->count_context));
    for (i = 0; i < vc_handl->count_context; i++)
    {
        vc_handl->context[i] = (char *)malloc(strlen(context[i]) + 2);
        strcpy(vc_handl->context[i], context[i]);
    }

    strcpy(vc_handl->id, id);

    vc_handl->count_type = count_type;
    vc_handl->type = (char **)malloc(sizeof(char *) * vc_handl->count_type);
    memset(vc_handl->type, 0, sizeof(sizeof(char *) * vc_handl->count_type));
    for (i = 0; i < vc_handl->count_type; i++)
    {
        vc_handl->type[i] = (char *)malloc(strlen(type[i]) + 2);
        strcpy(vc_handl->type[i], type[i]);
    }

    strcpy(vc_handl->sub_type, sub_type);
    strcpy(vc_handl->issuer, issuer);
    strcpy(vc_handl->issuance_data, issuance_data);
    strcpy(vc_handl->expiration_data, expiration_data);
    strcpy(vc_handl->description, description);

    vc_handl->count_subject = count_subject;
    vc_handl->CredentialSubject = (char **)malloc(sizeof(char *) * vc_handl->count_subject);
    memset(vc_handl->CredentialSubject, 0, sizeof(sizeof(char *) * vc_handl->count_subject));

    for (i = 0; i < vc_handl->count_subject; i++)
    {
        vc_handl->CredentialSubject[i] = (char *)malloc(strlen(CredentialSubject[i]) + 2);
        strcpy(vc_handl->CredentialSubject[i], CredentialSubject[i]);
    }

    strcpy(vc_handl->vcProof.type, vcProof->type);
    strcpy(vc_handl->vcProof.created, vcProof->created);
    strcpy(vc_handl->vcProof.verification_method, vcProof->verification_method);
    strcpy(vc_handl->vcProof.proof_purpose, vcProof->proof_purpose);
    strcpy(vc_handl->vcProof.JWSSignature, vcProof->JWSSignature);
    memcpy(vc_handl->vcProof.public_key, vcProof->public_key, 65);
    vc_handl->revoked = revoked;

    return vc_handl;
}

VP *new_vp(char *const*context,const int count_text,char *const*type,const int count_type,VC *const*vc,const int count_vc,const char *holder,const VPProof *vpProof)
{
    VP *vp_hand = create_vp_handle();
    int i = 0;
    vp_hand->count_context = count_text;
    vp_hand->context = (char **)malloc(sizeof(char *) * vp_hand->count_context);
    memset(vp_hand->context, 0, sizeof(sizeof(char *) * vp_hand->count_context));
    for (i = 0; i < vp_hand->count_context; i++)
    {
        vp_hand->context[i] = (char *)malloc(strlen(context[i]) + 2);
        strcpy(vp_hand->context[i], context[i]);
    }

    vp_hand->count_type = count_type;
    vp_hand->type = (char **)malloc(sizeof(char *) * vp_hand->count_type);
    memset(vp_hand->type, 0, sizeof(sizeof(char *) * vp_hand->count_type));
    for (i = 0; i < vp_hand->count_type; i++)
    {
        vp_hand->type[i] = (char *)malloc(strlen(type[i]) + 2);
        strcpy(vp_hand->type[i], type[i]);
    }

    vp_hand->count_vc = count_vc;
    vp_hand->vc = (VC **)malloc(sizeof(VC *) * vp_hand->count_vc);
    memset(vp_hand->vc, 0, sizeof(sizeof(VC *) * vp_hand->count_vc));
    for (i = 0; i < vp_hand->count_vc; i++)
    {
        vp_hand->vc[i] = vc[i];
    }
    strcpy(vp_hand->holder, holder);

    strcpy(vp_hand->vpProof.type, vpProof->type);
    strcpy(vp_hand->vpProof.created, vpProof->created);
    strcpy(vp_hand->vpProof.verification_method, vpProof->verification_method);
    strcpy(vp_hand->vpProof.proof_purpose, vpProof->proof_purpose);
    strcpy(vp_hand->vpProof.JWSSignature, vpProof->JWSSignature);
    strcpy(vp_hand->vpProof.nonce, vpProof->nonce);
    memcpy(vp_hand->vpProof.public_key, vpProof->public_key, 65);

    return vp_hand;
}

void jws_signature(const unsigned char *hash, did_handle did, char *sig)
{
    unsigned char sign[65] = {0};

    const char *algo = "{\"alg\":\"ES256\"}";
    char algo_base64[64] = {0};
    base64_urlraw_encode(algo, strlen(algo), algo_base64);

    const char hash_base64[64] = {0};
    base64_urlraw_encode(hash, 32, hash_base64);

    char payload[128] = {0};
    sprintf(payload, "%s.%s", algo_base64, hash_base64);

    char payload_hash[32] = {0};
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, payload, strlen(payload));
    sha256_final(&ctx, payload_hash);

    did_sign_hash(did, payload_hash, sign, 65);
    char sign_base64[128] = {0};
    base64_urlraw_encode(sign, 64, sign_base64);

    sprintf(sig, "%s..%s", algo_base64, sign_base64);
}

int jws_verify(const char *hash, const char *proof_type, const char *pubkey, const char *sign_jws)
{
    const char *sign_base64 = strrchr(sign_jws, '.');
    if (sign_base64 == NULL)
    {
        return -1;
    }

    unsigned char sign[64] = {0};
    base64_urlraw_decode(sign_base64 + 1, strlen(sign_base64 + 1), sign);

    const char *algo = "{\"alg\":\"ES256\"}";
    char algo_base64[64] = {0};
    base64_urlraw_encode(algo, strlen(algo), algo_base64);

    const char hash_base64[64] = {0};
    base64_urlraw_encode(hash, 32, hash_base64);

    char payload[128] = {0};
    sprintf(payload, "%s.%s", algo_base64, hash_base64);

    char payload_hash[32] = {0};
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, payload, strlen(payload));
    sha256_final(&ctx, payload_hash);

    did_key_t did_keys;
    memset(&did_keys, 0, sizeof(did_key_t));
    strcpy(did_keys.type,"EcdsaSecp256k1VerificationKey2019");
    
    
    return nodid_verify_hash_with_pubkey(&did_keys, pubkey, payload_hash, sign, 64);
}

void vc_signature(VC *vc, did_handle did, char *sig)
{
    // unsigned char vc_hash[32] = {0};
    // convert_vc_to_bytes(vc, vc_hash);
    char out[1024] = {0};
    char vcProof_jws[128] = {0};
    strcpy(vcProof_jws, vc->vcProof.JWSSignature);
    strcpy(vc->vcProof.JWSSignature, "");
    int out_len = 0;
    convert_vc_to_bytes(vc, out, &out_len);
    strcpy(vc->vcProof.JWSSignature, vcProof_jws);
    unsigned char vc_hash[32] = {0};
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, out, out_len);
    sha256_final(&ctx, vc_hash);

    jws_signature(vc_hash, did, sig);
}

int vc_verify(VC *vc)
{
    // unsigned char vc_hash[32] = {0};
    // convert_vc_to_bytes(vc, vc_hash);
    char out[1024] = {0};
    char vcProof_jws[128] = {0};
    strcpy(vcProof_jws, vc->vcProof.JWSSignature);
    strcpy(vc->vcProof.JWSSignature, "");
    int out_len = 0;
    convert_vc_to_bytes(vc, out, &out_len);
    strcpy(vc->vcProof.JWSSignature, vcProof_jws);
    unsigned char vc_hash[32] = {0};
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, out, out_len);
    sha256_final(&ctx, vc_hash);
    return jws_verify(vc_hash, vc->vcProof.type, vc->vcProof.public_key, vc->vcProof.JWSSignature);
}

void vp_signature(VP *vp, did_handle did, char *sig)
{
    // unsigned char vp_hash[32] = {0};
    // convert_vp_to_bytes(vp, vp_hash);
    unsigned char out[4096] = {0};
    char vpProof_jws[128] = {0};
    strcpy(vpProof_jws, vp->vpProof.JWSSignature);
    printf("vpProof_jws: %s\n", vpProof_jws);
    strcpy(vp->vpProof.JWSSignature, "");
    printf("vp->vpProof.JWSSignature: %s\n", vp->vpProof.JWSSignature);
    int out_len = 0;
    convert_vp_to_bytes(vp, out, &out_len);
    printf("VP bytes:length=%d\n %s\n", out_len, out);
    
    strcpy(vp->vpProof.JWSSignature, vpProof_jws);
    printf("vp->vpProof.JWSSignature: %s\n", vp->vpProof.JWSSignature);
    unsigned char vp_hash[32] = {0};
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, out, out_len);
    sha256_final(&ctx, vp_hash);

    jws_signature(vp_hash, did, sig);
}

int vp_verify(VP *vp)
{
    for (int i = 0; i < vp->count_vc; i++)
    {
        // VC verify error
        if (vc_verify(vp->vc[i]) != 0)
        {
            return -1;
        }
    }

    // unsigned char vp_hash[32] = {0};
    // convert_vp_to_bytes(vp, vp_hash);
    char out[4096] = {0};
    char vpProof_jws[128] = {0};
    strcpy(vpProof_jws, vp->vpProof.JWSSignature);
    strcpy(vp->vpProof.JWSSignature, "");
    int out_len= 0 ;
    convert_vp_to_bytes(vp, out, &out_len);
    strcpy(vp->vpProof.JWSSignature, vpProof_jws);
    unsigned char vp_hash[32] = {0};
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, out, out_len);
    sha256_final(&ctx, vp_hash);

    return jws_verify(vp_hash, vp->vpProof.type, vp->vpProof.public_key, vp->vpProof.JWSSignature);
}

VCProof *new_vc_proof(const char *type, const char *created, const char *vm, const char *proof_purpose, const char *jws, const unsigned char*pub_key)
{
    VCProof *ret = (VCProof *)malloc(sizeof(VCProof));
    memset(ret, 0, sizeof(VCProof));
    strcpy(ret->type, type);
    strcpy(ret->created, created);
    strcpy(ret->verification_method, vm);
    strcpy(ret->proof_purpose, proof_purpose);
    if(jws == NULL)
        strcpy(ret->JWSSignature, "");
    else
        strcpy(ret->JWSSignature, jws);
    if(pub_key != NULL)
        memcpy(ret->public_key, pub_key, 65);
    return ret;
}

VPProof *new_vp_proof(const char *type, const char *created, const char *vm, const char *proof_purpose, const char *jws, const char *nonce, const unsigned char *pub_key)
{
    VPProof *ret = (VPProof *) malloc (sizeof(VPProof));
    memset(ret, 0, sizeof(VPProof));
    strcpy(ret->type, type);
    strcpy(ret->created, created);
    strcpy(ret->verification_method, vm);
    strcpy(ret->proof_purpose, proof_purpose);
    if(jws == NULL)
        strcpy(ret->JWSSignature, "");
    else
        strcpy(ret->JWSSignature, jws);
    if(pub_key != NULL)
        memcpy(ret->public_key, pub_key, 65);
    strcpy(ret->nonce, nonce);
    return ret;
}

int cmp_context(const void *a, const void *b)
{
    return strcmp((char *)a, (char *)b);
}

void convert_vc_to_bytes(const VC *vc, char *out, int *out_len)
{
    int i = 0;
    *out_len = 0;
    char text[2048] = {0};
    for (i = 0; i < vc->count_context; i++)
    {
        strcat(text, vc->context[i]);
    }

    char text_type[128] = {0};
    for (i = 0; i < vc->count_type; i++)
    {
        strcat(text_type, vc->type[i]);
    }

    char vcProof[600] = {0};
    strcat(vcProof, vc->vcProof.type);
    strcat(vcProof, vc->vcProof.created);
    strcat(vcProof, vc->vcProof.verification_method);
    strcat(vcProof, vc->vcProof.proof_purpose);
    strcat(vcProof, vc->vcProof.JWSSignature);
    unsigned long vcProof_before_jws = strlen(vcProof);
    memcpy(vcProof+vcProof_before_jws, vc->vcProof.public_key, 65);

    strcat(out, text);
    strcat(out, text_type);
    strcat(out, vc->issuer);
    strcat(out, vc->issuance_data);
    strcat(out, vc->expiration_data);
    strcat(out, vc->description);
    if(vc->count_type>=2)
    {
        if (strcmp("WifiAccess", vc->type[1]) == 0 || strcmp("MiningLicense", vc->type[1]) == 0)
        {
            char subject[256] = {0};
            for (i = 0; i < vc->count_subject; i++)
            {
                strcat(subject, vc->CredentialSubject[i]);
            }
            strcat(out, subject);
        }
    }
    *out_len+=strlen(out) + vcProof_before_jws + 65;//
    memcpy(out+strlen(out), vcProof, vcProof_before_jws + 65);//

//  printf("\n -----VC CONVERT \n%s\n -----\n",out);
//  strcat(out, vcProof);
}

void convert_vp_to_bytes(const VP *vp, char *out,int *out_len)
{
    int i = 0;
    *out_len = 0;
    
    char text[512] = {0};
    for (i = 0; i < vp->count_context; i++)
    {
        strcat(text, vp->context[i]);
    }

    char text_type[128] = {0};
    for (i = 0; i < vp->count_type; i++)
    {
        strcat(text_type, vp->type[i]);
    }

    char vc_vector[2048] = {0};
    int vc_vec_len = 0;
    for (i = 0; i < vp->count_vc; i++)
    {
        char vc_out[2048] = {0};
        int vc_out_len = 0;
        convert_vc_to_bytes(vp->vc[i], vc_out, &vc_out_len);
        memcpy(vc_vector, vc_out, vc_out_len);
        vc_vec_len += vc_out_len;
    }

    char vpProof[600] = {0};
    strcat(vpProof, vp->vpProof.type);
    strcat(vpProof, vp->vpProof.created);
    strcat(vpProof, vp->vpProof.verification_method);
    strcat(vpProof, vp->vpProof.proof_purpose);
    strcat(vpProof, vp->vpProof.JWSSignature);
    strcat(vpProof, vp->vpProof.nonce);
    unsigned long vpProof_before_nonce=strlen(vpProof);
    memcpy(vpProof + vpProof_before_nonce, vp->vpProof.public_key, 65);

    strcat(out, text);
    strcat(out, text_type);
    memcpy(out+strlen(out), vc_vector, vc_vec_len);
    *out_len += strlen(text);
    *out_len += strlen(text_type);
    *out_len += vc_vec_len;
    
    memcpy(out + *out_len, vp->holder, strlen(vp->holder));
    *out_len += strlen(vp->holder);
    
    memcpy(out+*out_len, vpProof, vpProof_before_nonce + 65);//
    *out_len += (vpProof_before_nonce + 65);//
    //  strcat(out, vpProof);
//    printf("\n *****VP convert \n%s\n *****\n",out);
}
