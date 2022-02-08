#include "key_generator.h"
#include "stdlib.h"
#include "time.h"
#include "secp256k1/seck256k1_key.h"

static int default_rand_func(int len, unsigned char* buffer);

int default_rand_func(int len, unsigned char* buffer) 
{
    srand(time(NULL));
    
    for (int i = 0; i < len; i++)
    {
        buffer[i] = (unsigned char)(rand() % 256);
    }

    return len;
}

void generate_key_pair(rand_func_cb rand_func, char* algo, key_pair_t* key_pair)
{
    if (rand_func == NULL) 
    {
        rand_func = default_rand_func;
    }
    
    if (strcmp("algo", "secp256k1") == 0) 
    {
        generate_secp256k1_keypair(rand_func, key_pair);
        return;
    }
}