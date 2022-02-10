#include "did.h"
#include "stdlib.h"
#include "string.h"
#include "cJSON/cJSON.h"
#include "common/base64.h"

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
    if (handle == NULL) 
    {
        return NULL;
    }
    
    generate_key_pair(rand_func, algo, &handle->key_pair);
    strcpy(handle->algo, algo);

    return handle;    
}

void did_destroy(did_handle handle) 
{
    if (handle == NULL) 
    {
        return;
    }

    free(handle);
}

int did_serialize(did_handle handle, char* buffer, int buff_len) 
{
    did_context_t* context = (did_context_t*)handle;

    cJSON* did_root = NULL;
    cJSON* key_root = NULL;
    char*  privkey_base64 = NULL;
    char*  pubkey_base64 = NULL;
    int    privkey_base64_len = 0;
    int    pubkey_base64_len = 0;
    int    result = -1;
    char*  json_str = NULL;

    did_root = cJSON_CreateObject();
    if (cJSON_AddStringToObject(did_root, "algo", context->algo) == NULL)
    {
        goto RET;
    }
    
    privkey_base64_len = base64_encode(context->key_pair.priv, context->key_pair.priv_len, NULL);
    pubkey_base64_len = base64_encode(context->key_pair.pubkey, context->key_pair.pubkey_len, NULL);

    privkey_base64 = (char*)malloc(privkey_base64_len);
    if (privkey_base64 == NULL) 
    {
        goto RET;
    }
    base64_encode(context->key_pair.priv, context->key_pair.priv_len, privkey_base64);

    pubkey_base64 = (char*)malloc(pubkey_base64_len);
    if (pubkey_base64 == NULL) 
    {
        goto RET;
    }
    base64_encode(context->key_pair.pubkey, context->key_pair.pubkey_len, pubkey_base64);

    key_root = cJSON_CreateObject();
    if (cJSON_AddStringToObject(key_root, "priv", privkey_base64) == NULL) 
    {
        goto RET;
    }

    if (cJSON_AddStringToObject(key_root, "pub", pubkey_base64) == NULL) 
    {
        goto RET;
    }

    if (cJSON_AddItemToObject(did_root, "key_pari", key_root) != cJSON_True) 
    {
        goto RET;
    }
    
    key_root = NULL;
    json_str = cJSON_Print(did_root);
    if (json_str == NULL) 
    {
        goto RET;
    }

    if (buffer == NULL || buff_len <= 0) 
    {
        result = strlen(json_str) + 1;
        goto RET;
    }
    
    if (buff_len <= strlen(json_str)) 
    {
        strncpy(buffer, json_str, buff_len - 1);
        result = buff_len;
    } 
    else 
    {
        strcpy(buffer, json_str);
        result = strlen(json_str) + 1;
    }

RET:
    if (did_root != NULL) 
    {
        cJSON_Delete(did_root);
    }
    
    if (key_root != NULL) 
    {
        cJSON_Delete(key_root);
    }
    
    if (privkey_base64 != NULL) 
    {
        free(privkey_base64);
    }

    if (pubkey_base64 != NULL) 
    {
        free(pubkey_base64);
    }
    
    if (json_str != NULL) 
    {
        free(json_str);
    }

    return result;
}

did_handle did_deserialize(const char* buffer, int buff_len) {

}