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
    
//    did_handle handle3 = did_import_privkey("secp256k1.2e6ad25111f09beb080d556b4ebb824bace0e16c84336c8addb0655cdbaade09");
    //zPYHK5ZNAzqo2PQ11r54Ku8p2qrwn42ebt7qM4827vAvGuMUV65EKFR7CqmKuvkKJuXPyNrZd8WG3jiqcSzLzpdg9
//    char* context[2] ={"https://www.w3.org/2018/credentials/v1","https://ns.did.ai/suites/secp256k1-2019/v1/"};
    
//    char* type[2] = {"VerifiableCredential","PermanentResidentCard"};
//
//    char* subject[6] = {
//        //"1",
//        "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
//        "John",
//        "Jacobs",
//        "Male",
//        "Canada",
//        "2022-03-22"
//    };
    
    did_handle did_vc_test = did_import_privkey("secp256k1.dbbd9634560466ac9713e0cf10a575456c8b55388bce0c044f33fc6074dc5ae6");
    
    did_meta_t* vc_did_meta = did_to_did_meta(did_vc_test);
    
    unsigned char vc_did_pubkey[65] = {0};
    did_get_pubkey(did_vc_test, vc_did_pubkey, 65);

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
    printf("\n--vc proof jws:\n%s\n---",vc2->vcProof.JWSSignature);
    
    verify = vc_verify(vc2);
    printf("\nVC2 verify result %d\n", verify);
    
    //-----create vp and verify
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
    VPProof* vpProof = new_vp_proof("EcdsaSecp256k1Signature2019", "2022-03-31T12:53:19-07:00", "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification", "Authentication", NULL, "sampleNonce", vc_did_pubkey);
    VC* vc_vector[1] = {vc2};
    
    VP* vp = new_vp(context_vp, 2, type_vp, 1, vc_vector, 1, "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX", vpProof);
    
    vp_signature((VP*)vp, did_vc_test, vp->vpProof.JWSSignature);
    printf("\n--vp jws:\n%s\n---",vp->vpProof.JWSSignature);

    
    verify = vp_verify((VP*)vp);
    printf("\nVP verify result %d\n", verify);
    
    return 0;
}
