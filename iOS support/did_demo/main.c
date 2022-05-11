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
    // did signature process
    did_sign(did, "Hello, World!", strlen("Hello, World!"), sig, 65);
    
    // get did document from storage
    did_meta_t* did2_meta = did_to_did_meta(did2);
    
    // verify signature and unsigned content with public key
    int verify = did_verify(did2_meta->did_keys, "Hello, World!", strlen("Hello, World!"), sig, 65);
    
    
    did_handle handle3 = did_import_privkey("secp256k1.2e6ad25111f09beb080d556b4ebb824bace0e16c84336c8addb0655cdbaade09");
    
    printf("Hello, World! Verify result %d\n", verify);
    
    VCProof* vcProof = new_vc_proof("EcdsaSecp2556k1Signature2019", "2022-03-31T12:53:19-07:00", "did:metablox:HFXPiudexfvsJBqABNmBp785YwaKGjo95kmDpBxhMMYo#verification", "Authentication");
    
    char* context[2]={"https://www.w3.org/2018/credentials/v1","https://na.did.ai/suites/secp256k1-2019/v1"};
    
    char* type[2]={"VerifiableCredential","PermanentResidentCard"};
    
    char* subject[6]={"did:metablox:HFXPiudexdid:metablox:HFXPiudexfvsJBqABNmBp785YwaKGjo95kmDpBxhMMYo","John","Jacobs","Male","Canada","2022-03-22"};
    
    vc_handle vc1=new_vc(context, 2, "http://metablox.com/credentials/1", type, 2, "PermanentResidentCard", "did:metablox:sampleIssuer", "2022-03-31T12:53:19-07:00", "2022-03-31T12:53:19-07:00", "Government of Example Permanent Resident Card", subject, 6, *vcProof, 0);

    char out[64] = {0};
    ConvertVPToBytes(vc1, out);

    char sig1[64] = {0};
    did_sign(did, out, 32, sig1, 64);
    
    CreatJWSSignature(vc1, sig1);
    VC* vc = (VC*)vc1;
    verify = did_verify(did2_meta->did_keys, out, 32, vc->vcProof.JWSSignature, 64);

    //verify=verifyVC(vc1, did);
    printf("\n ------verifyVC:%d",verify);
    
    return 0;
}
