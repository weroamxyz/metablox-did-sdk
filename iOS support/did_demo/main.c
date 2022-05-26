//
//  main.c
//  did_demo
//
//  Created by liudeng on 2022/2/23.
//

#include <stdio.h>
#include "did_wallet/did_wallet.h"
#include "did/did.h"
#include "string.h"
#include "models/models.h"
#include "keccak256/keccak256.h"

int main(int argc, const char *argv[])
{
    // insert code here...
    char buffer1[2048] = {0};
    char buffer2[2048] = {0};
    size_t buff_len = 2048;
    did_handle did = did_create("secp256k1", NULL);

    wallet_handle wallet = wallet_handle_create("test", "/tmp/DIDTest");

    wallet_store_did(wallet, did, "test-did", "12345678");

    did_handle did2 = wallet_load_did(wallet, "test-did", "12345678");

    did_serialize(did, buffer1, buff_len);

    did_serialize(did2, buffer2, buff_len);

    // Did signature output
    char sig[65] = {0};
    unsigned char hash[32] = {0};

    SHA3_CTX sha3_ctx;
    keccak_init(&sha3_ctx);
    keccak_update(&sha3_ctx, "HelloWorld", strlen("HelloWorld"));
    keccak_final(&sha3_ctx, hash);

    // did signature process
    did_sign_hash(did, hash, sig, 65);

    // get did document from storage
    did_meta_t* did2_meta = did_to_did_meta(did2);

    // verify signature and unsigned content with public key
    int verify = did_verify_hash(did2_meta->did_keys, hash, sig, 65);
    printf("\n Verify Hello, World! result %d\n", verify);

    //------creat vc and verify
    did_handle did_vc_test = did_import_privkey("secp256k1.dbbd9634560466ac9713e0cf10a575456c8b55388bce0c044f33fc6074dc5ae6");
    
    unsigned char vc_did_pubkey[65] = {0};
    did_get_pubkey(did_vc_test, vc_did_pubkey, 65);
    //    unsigned char pubkey[65]={4, 103, 89, 134, 238, 118, 86, 61, 43, 58, 216, 220, 171, 26, 136, 74, 220, 205, 222, 156, 30, 162, 206, 49, 234, 95, 43, 142, 116, 148, 41, 186, 156, 198, 8, 168, 219, 47, 3, 102, 97, 180, 96, 99, 19, 32, 179, 209, 93, 56, 16, 195, 2, 144, 196, 166, 145, 6, 168, 114, 247, 0, 246, 116, 118};
    char* context_vc[2] = {"https://www.w3.org/2018/credentials/v1","https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#"};
    
    char* type_vc[2] = {"VerifiableCredential","PermanentResidentCard"};
    
    char* subject_vc[6] = {
            //"1",
            "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
            "John",
            "Jacobs",
            "Male",
            "Canada",
            "2022-03-22"
        };
    
    VCProof* vcProof_vc = new_vc_proof("EcdsaSecp256k1Signature2019", "2022-03-31T12:53:19-07:00", "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification", "Authentication", NULL, vc_did_pubkey);
    
    VC* vc2 = new_vc(context_vc, 2, "http://metablox.com/credentials/1", type_vc, 2, "PermanentResidentCard", "did:metablox:sampleIssuer", "2022-03-31T12:53:19-07:00", "2032-03-31T12:53:19-07:00", "Government of Example Permanent Resident Card", subject_vc, 6, vcProof_vc, 0);

    vc_signature((VC*)vc2, did_vc_test, vc2->vcProof.JWSSignature);
    printf("\n----vc proof jws:\n%s\n----", vc2->vcProof.JWSSignature);
    
    verify = vc_verify(vc2);
    printf("\n VC veriry result:%d\n",verify);
    
    //----creat vp and verify
    char* context_vp[2] = {"https://www.w3.org/2018/credentials/v1","https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#"};
    
    char* type_vp[1] = {"VerifiablePresentation"};
    
    VPProof* vpProof = new_vp_proof("EcdsaSecp256k1Signature2019", "2022-03-31T12:53:19-07:00", "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification", "Authentication", NULL, "sampleNonce", vc_did_pubkey);
    
    VC* vc_vector[1] = {vc2};

    VP* vp = new_vp(context_vp, 2, type_vp, 1, vc_vector, 1, "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX", vpProof);

    vp_signature((VP*)vp, did_vc_test, vp->vpProof.JWSSignature);
    printf("\n ----VP proof jws:\n%s\n ----", vp->vpProof.JWSSignature);
    
    verify = vp_verify((VP*)vp);
    printf("\nVP verify result %d\n", verify);

    return 0;
}

