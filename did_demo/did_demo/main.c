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

int main(int argc, const char * argv[]) {
    // insert code here...
    char buffer1[2048] = {0};
    char buffer2[2048] = {0};
    size_t buff_len = 2048;
    // create did
    did_handle did = did_create("secp256k1", NULL);
    
    // Set a local directory for did storage
    // Must replace with an existing directory
    wallet_handle wallet= wallet_handle_create("test", "/tmp/DIDTest");
    
    // Store did into a file with encrypt keyword
    wallet_store_did(wallet, did, "test-did", "1234567887654321");
    
    // test retrieving did from storage
    did_handle did2 = wallet_load_did(wallet, "test-did", "1234567887654321");
    
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
    
    did_handle handle3 = did_import_privkey("secp256k1.2e6ad25111f09beb080d556b4ebb824bace0e16c84336c8addb0655cdbaade09");
    //zPYHK5ZNAzqo2PQ11r54Ku8p2qrwn42ebt7qM4827vAvGuMUV65EKFR7CqmKuvkKJuXPyNrZd8WG3jiqcSzLzpdg9
    
    VCProof* vcProof = new_vc_proof("EcdsaSecp256k1Signature2019", "2022-03-31T12:53:19-07:00", "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification", "Authentication", NULL);
    
    char* context[2] = {"https://www.w3.org/2018/credentials/v1","https://ns.did.ai/suites/secp256k1-2019/v1/"};
    
    char* type[2] = {"VerifiableCredential","PermanentResidentCard"};
    
    char* subject[6] = {
        //"1",
        "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
        "John",
        "Jacobs",
        "Male",
        "Canada",
        "2022-03-22"
    };
    
    did_handle did_vc_test = did_import_privkey("secp256k1.dbbd9634560466ac9713e0cf10a575456c8b55388bce0c044f33fc6074dc5ae6");
    VC* vc1 = new_vc(context, 2, "http://metablox.com/credentials/1", type, 2, "PermanentResidentCard", "did:metablox:sampleIssuer", "2022-03-31T12:53:19-07:00", "2032-03-31T12:53:19-07:00", "Government of Example Permanent Resident Card", subject, 6, *vcProof, 0);
    
    vc_signature((VC*)vc1, did_vc_test, vc1->vcProof.JWSSignature);
    printf("\n--vc proof jws:\n%s\n---\n",vc1->vcProof.JWSSignature);
    did_meta_t* vc_did_meta = did_to_did_meta(did_vc_test);
    unsigned char vc_did_pubkey[65] = {0};
    did_get_pubkey(did_vc_test, vc_did_pubkey, 65);
    verify = vc_verify((VC*)vc1, vc_did_meta, vc_did_pubkey);
    printf("\n VC 1 verify result %d\n", verify);
    
    
    //vp test
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
    VCProof* vcProof_vc = new_vc_proof("EcdsaSecp256k1Signature2019", "2022-03-31T12:53:19-07:00", "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification", "Authentication","" /*"eyJhbGciOiJFUzI1NiJ9..uXiwqwehyniumzaVlcOQSCfbe6xstKE7zapUN2bWeDn9bI9rEUETl8duT2ej_7GFB2BUu5nh09t3zKIfV-4aiQ"*/);
    VC* vc2 = new_vc(context_vc, 2, "http://metablox.com/credentials/1", type_vc, 2, "PermanentResidentCard", "did:metablox:sampleIssuer", "2022-03-31T12:53:19-07:00", "2032-03-31T12:53:19-07:00", "Government of Example Permanent Resident Card", subject_vc, 6, *vcProof_vc, 0);
    
    vc_signature((VC*)vc2, did_vc_test, vc2->vcProof.JWSSignature);
    
    char* context_vp[2] = {"https://www.w3.org/2018/credentials/v1","https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#"};
    char* type_vp[1] = {"VerifiablePresentation"};
    char* subject_vp[6] = {
        //"1",
        "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
        "John",
        "Jacobs",
        "Male",
        "Canada",
        "2022-03-22"
    };
    VPProof* vpProof = new_vp_proof("EcdsaSecp256k1Signature2019", "2022-03-31T12:53:19-07:00", "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification", "Authentication", "", "sampleNonce");
    VC* vc_vector[1] = {vc2};
    
    VP* vp = new_vp(context_vp, 2, type_vp, 1, vc_vector, 1, "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX", vpProof);
    
    vp_signature((VP*)vp, did_vc_test, vp->vpProof.JWSSignature);
    did_meta_t *vec_meat[1]={vc_did_meta};
    char *vec_publickey[1]={vc_did_pubkey};
    
    verify = vp_verify((VP*)vp, vc_did_meta, vc_did_pubkey, vec_meat, vec_publickey);
    printf("\nVP verify result %d\n", verify);
    
    return 0;
}
