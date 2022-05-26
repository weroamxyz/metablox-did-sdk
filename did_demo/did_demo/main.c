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

int main(int argc, const char *argv[])
{
    // insert code here...
    char buffer1[2048] = {0};
    char buffer2[2048] = {0};
    size_t buff_len = 2048;
    did_handle did = did_create("secp256k1", NULL);

    wallet_handle wallet = wallet_handle_create("test-did", "/home/meiqiu/doc/did_sdk-main2/build/test");

    wallet_store_did(wallet, did, "test-did", "12345678");

    did_handle did2 = wallet_load_did(wallet, "test-did", "12345678");

    did_serialize(did, buffer1, buff_len);

    did_serialize(did2, buffer2, buff_len);

    char sig[64] = {0};
    int did_sign_res = did_sign(did, "Hello, World!", strlen("Hello, World!"), sig, 64);
    // printf("\n\n\tsig:%s,          did_sign_res:%d",sig,did_sign_res);

    did_meta_t *did2_meta = did_to_did_meta(did2);

    int verify = did_verify(did2_meta->did_keys, "Hello, World!", strlen("Hello, World!"), sig, 64);
    // printf("\n this verify result:%d",verify);

    // 2022.5.2
    VCProof *vcProof = new_vc_proof("EcdsaSecp256k1Signature2019",
                                    "2022-03-31T12:53:19-07:00",
                                    "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification",
                                    "Authentication");
    // "eyJhbGciOiJFUzI1NiJ9..SnGaW3ya8MM-DXbRSFXWHM_R7Vg_3u_u1OxEfxvwXzQWNRmmC5noWvleSEM3iQdofm7towbpJ6nABQs9e1-OvA"

    char *context[2] = {"https://ns.did.ai/suites/secp256k1-2019/v1/",
                        "https://www.w3.org/2018/credentials/v1"};

    char *type[2] = {"PermanentResidentCard",
                     "VerifiableCredential"};

    char *subject[6] = {"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
                        "John",
                        "Jacobs",
                        "Male",
                        "Canada",
                        "2022-03-22"};

    vc_handle vc1 = new_vc(context, 2,
                           "http://metablox.com/credentials/1",
                           type, 2,
                           "PermanentResidentCard",
                           "did:metablox:sampleIssuer",
                           "2022-03-31T12:53:19-07:00",
                           "2032-03-31T12:53:19-07:00",

                           "Government of Example Permanent Resident Card", // "Government of Example Permanent Resident Card",
                           subject, 6,
                           *vcProof, 0);

    char out[1024]={0};     
    // did_sign(did,)  
    vc_to_json(vc1,out);
    // printf("\n -----------vc to json:%s", out);
    verify=verify_vc(vc1,did);
    vc_handle vc2= json_to_vc(out);

    //*******vp
    VPProof *vpProof = new_vp_proof("EcdsaSecp256k1Signature2019",
                                    "2022-03-31T12:53:19-07:00",
                                    "did:metablox:HFXPiudexfvsJBqABNmBp785YwaKGjo95kmDpBxhMMYo#verification",
                                    "Authentication","sampleNonce");

    vc_handle vc_vec[1] = {vc1};

    char *context1[2] = {"https://www.w3.org/2018/credentials/v1", "https://ns.did.ai/suites/secp256k1-2019/v1/"};
    char *type1[1] = {"VerifiablePresentation"};
    vp_handle vp = new_vp(context1, 2,
                          type1, 1, vc_vec, 1,
                          "did:metablox:HFXPiudexfvsJBqABNmBp785YwaKGjo95kmDpBxhMMYo",
                          vpProof);

    // verify=verifyVP(vp,did);
    char out2[1024]={0};
    // convert_vp_toBytes(vp,out2);
    printf("\n out2:%s", out2);
    printf("\n -----------verifyVP:%d", verify);

    vc_destroy(vc1);
    vp_destroy(vp);

    printf("\nHello, World! Veri result %d\n", verify);
    return 0;
}

