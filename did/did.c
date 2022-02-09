#include "did.h"
#include "stdlib.h"
#include "string.h"

typedef struct did_context_tag {
    key_pair_t  key_pair;
    char        algo[64];
} did_context_t;

did_handle did_create(const char* algo, rand_func_cb rand_func) 
{   
    if (strlen(algo) > 63) 
    {
        // Algo length overflow
        return;
    }

    did_context_t* handle = (did_context_t*)malloc(sizeof(did_context_t));
    if (handle == NULL) {
        return NULL;
    }
    
    generate_key_pair(rand_func, algo, &handle->key_pair);
    strcpy(handle->algo, algo);

    return handle;    
}

void did_destroy(did_handle handle) 
{
    if (handle == NULL) {
        return;
    }

    free(handle);
}

int did_serialize(did_handle handle, char* buffer, int buff_len) 
{
    
}

did_handle did_deserialize(const char* buffer, int buff_len) {

}