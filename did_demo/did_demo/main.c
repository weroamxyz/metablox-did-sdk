//
//  main.c
//  did_demo
//
//  Created by liudeng on 2022/2/23.
//

#include <stdio.h>
#include "did_wallet/did_wallet.h"

int main(int argc, const char * argv[]) {
    // insert code here...
    
    wallet_handle handle= wallet_handle_create("test", "/Users/liudeng/liziTest/test");
    
    printf("Hello, World!\n");
    return 0;
}
