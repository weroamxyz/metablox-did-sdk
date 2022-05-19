#include "models/models.h"
#include "stdlib.h"
#include "string.h"
#include "stddef.h"
#include "common/sha256.h"
#include "common/base64.h"
#include "common/base58.h"
#include "stdio.h"

static void jws_signature(const char* hash, did_handle did, char *sig);

vc_handle create_vc_handle()
{
   VC *vc_handl = (VC *)malloc(sizeof(VC));
   if (vc_handl == NULL)
      return NULL;
   memset(vc_handl, 0, sizeof(VC));
   return vc_handl;
}

vp_handle create_vp_handle()
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
         {
                // if(i<4) ??
                // free(vc_handl->CredentialSubject[i]);
         }
      }
   }
   // free(vc_handl->CredentialSubject);//?? = why can`t
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
   // if (vp_hand->vc != NULL && vp_hand->count_vc >= 0)
   // {
   //        for (i = 0; i < vp_hand->count_vc; i++)
   //        {
   //               if (vp_hand->type[i] != NULL)
   //                      vc_destroy(vp_hand->vc[i]);
   //        }
   // }
   // free(vp_hand->vc);
   free(vp_hand);
}

vc_handle new_vc(char **context, int count_text, char *id,
                 char **type, int count_type, char *sub_type, char *issuer,
                 char *issuance_data, char *expiration_data, char *description,
                 char **CredentialSubject, int count_subject,
                 VCProof vcProof, int revoked)
{
   VC *vc_handl = create_vc_handle();
   // todo !!!use memcpy
   int i = 0;
   vc_handl->count_context = count_text;
   vc_handl->context = (char **)malloc(sizeof(char *) * vc_handl->count_context);
   memset(vc_handl->context, 0, sizeof(sizeof(char *) * vc_handl->count_context));
   for (i = 0; i < vc_handl->count_context; i++)
   {
          vc_handl->context[i] = (char *)malloc(strlen(context[i] + 2));
          strcpy(vc_handl->context[i], context[i]);
          // printf("\n vc_handle->contest:%s",vc_handl->context[i]);
   }
   // vc_handl->context = context;

   strcpy(vc_handl->id, id);

   vc_handl->count_type = count_type;
   vc_handl->type = (char **)malloc(sizeof(char *) * vc_handl->count_type);
   memset(vc_handl->type, 0, sizeof(sizeof(char *) * vc_handl->count_type));
   for (i = 0; i < vc_handl->count_type; i++)
   {
          vc_handl->type[i] = (char *)malloc(strlen(type[i] + 2));
          strcpy(vc_handl->type[i], type[i]);
          // printf("\n vc_handle->contest:%s",vc_handl->type[i]);
   }
   // vc_handl->type = type;

   strcpy(vc_handl->sub_type, sub_type);
   strcpy(vc_handl->issuer, issuer);
   strcpy(vc_handl->issuance_data, issuance_data);
   strcpy(vc_handl->expiration_data, expiration_data);
   strcpy(vc_handl->description, description);

   vc_handl->count_subject = count_subject;
   vc_handl->CredentialSubject = (char **)malloc(sizeof(char *) * vc_handl->count_subject);
   memset(vc_handl->CredentialSubject, 0, sizeof(sizeof(char *) * vc_handl->count_subject));
   printf("\n vc_handle.subujecCount:%d", vc_handl->count_subject);
   for (i = 0; i < vc_handl->count_subject; i++)
   {
          vc_handl->CredentialSubject[i] = (char *)malloc(strlen(CredentialSubject[i] + 2));
          strcpy(vc_handl->CredentialSubject[i], CredentialSubject[i]);
          // printf("\n vc_handle->contest:%s",vc_handl->CredentialSubject[i]);
   }
   // vc_handl->CredentialSubject = CredentialSubject;

   strcpy(vc_handl->vcProof.type, vcProof.type);
   strcpy(vc_handl->vcProof.created, vcProof.created);
   strcpy(vc_handl->vcProof.verification_method, vcProof.verification_method);
   strcpy(vc_handl->vcProof.proof_purpose, vcProof.proof_purpose);
   vc_handl->revoked = revoked;

//       char out[2048] = {0};
//       ConvertVCToBytes(vc_handl, out);
//
//       char hash[32] = {0};
//       SHA256_CTX ctx;
//       sha256_init(&ctx);
//       sha256_update(&ctx, out, strlen(out));
//       sha256_final(&ctx, hash);
//
//       char sig[64] = {0};
//       did_sign(did, hash, 32, sig, 64);
//
//       memcpy(vc_handl->vcProof.JWSSignature, sig, 64);

   return vc_handl;
}

vp_handle new_vp(char **context, int count_text, char **type, int count_type, VC **vc, int count_vc, char *holder, VPProof *vpProof)
{
       VP *vp_hand = create_vp_handle();
       int i = 0;
       vp_hand->count_context = count_text;
       vp_hand->context = (char **)malloc(sizeof(char *) * vp_hand->count_context);
       memset(vp_hand->context, 0, sizeof(sizeof(char *) * vp_hand->count_context));
       for (i = 0; i < vp_hand->count_context; i++)
       {
              vp_hand->context[i] = (char *)malloc(strlen(context[i] + 2));
              strcpy(vp_hand->context[i], context[i]);
       }
       // vp_hand->context = context;

       vp_hand->count_type = count_type;
       vp_hand->type = (char **)malloc(sizeof(char *) * vp_hand->count_type);
       memset(vp_hand->type, 0, sizeof(sizeof(char *) * vp_hand->count_type));
       for (i = 0; i < vp_hand->count_type; i++)
       {
              vp_hand->type[i] = (char *)malloc(strlen(type[i] + 2));
              strcpy(vp_hand->type[i], type[i]);
              // printf("\n vc_handle->contest:%s",vc_handl->type[i]);
       }
       // vp_hand->type = type;

       // Copy or assign vc ???
       vp_hand->vc = vc;
       vp_hand->count_vc = count_vc;
       strcpy(vp_hand->holder, holder);

       strcpy(vp_hand->vpProof.type, vpProof->type);
       strcpy(vp_hand->vpProof.created, vpProof->created);
       strcpy(vp_hand->vpProof.verification_method, vpProof->verification_method);
       strcpy(vp_hand->vpProof.proof_purpose, vpProof->proof_purpose);
       // vp_hand->vpProof.nonce = (char *)malloc(strlen(vpProof->nonce));
       // strcpy(vp_hand->vpProof.nonce, vpProof->nonce);

//       char out[2048] = {0};
//       ConvertVPToBytes(vp_hand, out);
//
//       char hash[32] = {0};
//       SHA256_CTX ctx;
//       sha256_init(&ctx);
//       sha256_update(&ctx, out, strlen(out));
//       sha256_final(&ctx, hash);
//
//       char sig[64] = {0};
//       did_sign(did, hash, 32, sig, 64);
//
//       memcpy(vp_hand->vpProof.nonce, sig, 64);

       return vp_hand;
}

void jws_signature(const char* hash, did_handle did, char *sig)
{
    unsigned char sign[65] = {0};
    
    const char* algo = "{\"alg\":\"ES256\"}";
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

void vc_signature(VC *vc, did_handle did, char *sig)
{
    unsigned char vc_hash[32] = {0};
    convert_vc_to_bytes(vc, vc_hash);
    
    jws_signature(vc_hash, did, sig);
}

int verify_vc(VC *vc, const did_meta_t* did, unsigned char* pubkey)
{
    return 0;
}

void vp_signature(VP* vp, did_handle did, char* sig)
{
    unsigned char vp_hash[32] = {0};
    convert_vp_to_bytes(vp, vp_hash);
    
    jws_signature(vp_hash, did, sig);
}

int verify_vp(VP* vp, const did_meta_t* holder_did, unsigned char* holder_pubkey, const did_meta_t* issuers_did, unsigned char* issuers_pubkey)
{
    return 0;
}

VCProof *new_vc_proof(char *type, char *created, char *vm, char *proof_purpose)
{
    VCProof *ret = (VCProof *)malloc(sizeof(VCProof));
    memset(ret, 0, sizeof(VCProof));
    strcpy(ret->type, type);
    strcpy(ret->created, created);
    strcpy(ret->verification_method, vm);
    strcpy(ret->proof_purpose, proof_purpose);
    return ret;
}

VPProof *new_vp_proof(char *type, char *created, char *vm, char *proof_purpose)
{
    VPProof *ret = (VPProof *)malloc(sizeof(VPProof));
    memset(ret, 0, sizeof(VPProof));
    strcpy(ret->type, type);
    strcpy(ret->created, created);
    strcpy(ret->verification_method, vm);
    strcpy(ret->proof_purpose, proof_purpose);
    return ret;
}

void convert_vc_to_bytes(VC *vc, char *hashout)
{
    int i = 0;
    char context[2048] = {0};
    for (i = 0; i < vc->count_context; i++)
    {
        strcat(context, vc->context[i]);
    }

    char type[80] = {0};
    for (i = 0; i < vc->count_type; i++)
    {
        strcat(type, vc->type[i]);
    }

    char CredentialSubject[256] = {0};
    for (i = 0; i < vc->count_subject; i++)
    {
        strcat(CredentialSubject, vc->CredentialSubject[i]);
    }

    char vcProof[600] = {0};
    strcat(vcProof, vc->vcProof.type);
    strcat(vcProof, vc->vcProof.created);
    strcat(vcProof, vc->vcProof.verification_method);
    strcat(vcProof, vc->vcProof.proof_purpose);

    char out[2048]={0};
    strcat(out, context);
    strcat(out, type);
    //strcat(out, vc->sub_type);
    strcat(out, vc->issuer);
    strcat(out, vc->issuance_data);
    strcat(out, vc->expiration_data);
    strcat(out, vc->description);
    strcat(out, CredentialSubject);
    strcat(out, vcProof);
    //char rev[4] = {0};
    //sprintf(rev, "%d", vc->revoked);
    //strcat(out, rev);
    printf("out value %s\n", out);
    char hash1[32] = {0};
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, out, strlen(out));
    sha256_final(&ctx, hash1);

    memcpy(hashout,hash1,32);
}

void convert_vp_to_bytes(VP *vp, char *hashout)
{
    int i = 0;
    char context[2048] = {0};
    for (i = 0; i < vp->count_context; i++)
    {
        strcat(context, vp->context[i]);
    }

    char type[80] = {0};
    for (i = 0; i < vp->count_type; i++)
    {
        strcat(type, vp->type[i]);
    }

    char vp_vector[2048] = {0};
    for (i = 0; i < vp->count_vc; i++)
    {
        if (vp->vc[i] != NULL)
        {
            char out[1024] = {0};
            convert_vc_to_bytes(vp->vc[i], out);
            // printf("\n ConvertVCToBytes:%s",out);
            strcat(vp_vector, out);
        }
    }

    char vpProof[600] = {0};
    strcat(vpProof, vp->vpProof.type);
    strcat(vpProof, vp->vpProof.created);
    strcat(vpProof, vp->vpProof.verification_method);
    strcat(vpProof, vp->vpProof.proof_purpose);
    // if (vp->vpProof.nonce != NULL)
    // {
    //        strcat(vpProof, vp->vpProof.nonce);
    // }

    char out[2048]={0};
    strcat(out, context);
    strcat(out, type);
    strcat(out, vp_vector);
    strcat(out, vp->holder);
    strcat(out, vpProof);

    char hash1[32] = {0};
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, out, strlen(out));
    sha256_final(&ctx, hash1);

    memcpy(hashout,hash1,32);
}
