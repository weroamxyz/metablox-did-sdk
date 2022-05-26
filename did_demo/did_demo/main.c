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
    int did_sign_result = did_sign(did, "Hello, World!", strlen("Hello, World!"), sig, 64);

    did_meta_t *did2_meta = did_to_did_meta(did2);

    int verify = did_verify(did2_meta->did_keys, "Hello, World!", strlen("Hello, World!"), sig, 64);

    // 2022.4.25
    // test namelist
    did_handle did5 = did_create("secp256k1", NULL);
    wallet_store_did(wallet, did5, "lufi", "468217586");

    wallet_did_nl namelist;
    wallet_get_namelist(wallet, &namelist);

    int i = 0;
    for (i = 0; i < namelist.count; i++)
    {
        printf("\n namelist :%s", namelist.names[i]);
    }
    did_wallet_free_namelist(&namelist);

    // test impotr export private key
    char prikey[128] = {0};
    did_export_prikey(did, prikey);
    printf("\n prikey:%s", prikey);

    did_handle did6 = did_import_privkey(prikey);
    char buffer6[2048] = {0};
    did_serialize(did6, buffer6, buff_len);
    printf("\n did:%p\n did buffer:%s", did, buffer1);
    printf("\n compare");
    printf("\n did6:%p\n did6 buffer:%s", did6, buffer6);

    printf("\nHello, World! Verif yesult %d\n", verify);
    return 0;
}
