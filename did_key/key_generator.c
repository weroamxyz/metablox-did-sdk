#include "key_generator.h"
#include "stdlib.h"
#include "time.h"

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

void generate_key(rand_func_cb rand_func, char* algo, key_pair_t* key_pair)
{
    if (rand_func == NULL) {
        rand_func = default_rand_func;
    }

    
}