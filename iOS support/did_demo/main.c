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
    
    printf("Hello, World! Verify result %d\n", verify);
    return 0;
}
