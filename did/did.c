#include "did.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "cJSON/cJSON.h"
#include "common/base64.h"
#include "common/base58.h"
#include "common/sha256.h"
#include <math.h>
#include "keccak256/keccak256.h"

typedef struct did_context_tag
{
    char did[MAX_DID_STR_LEN];
    char algo[64];
    key_pair_t key_pair;
} did_context_t;

did_handle did_create(const char *algo, rand_func_cb rand_func)
{
    if (strlen(algo) > 63)
    {
        // Algo length overflow
        return NULL;
    }

    did_context_t *handle = (did_context_t *)malloc(sizeof(did_context_t));
    if (handle == NULL)
    {
        return NULL;
    }
    memset(handle, 0, sizeof(did_context_t));

    generate_key_pair(rand_func, algo, &handle->key_pair);
    strcpy(handle->algo, algo);

	unsigned char hash[32] = {0};
    SHA3_CTX sha3_ctx;
    keccak_init(&sha3_ctx);
    keccak_update(&sha3_ctx, handle->key_pair.pubkey, handle->key_pair.pubkey_len);
    keccak_final(&sha3_ctx, hash);

    size_t base58_len = 64;
    b58_encode(hash, 32, handle->did, &base58_len);
    return handle;
}

void did_get_didstring(did_handle* did_handl,char* out)
{
    did_context_t *handle = (did_context_t *)did_handl;
    strcat(out, "did:mettablox:");
    strcat(out, handle->did);
}

void did_destroy(did_handle handle)
{
    if (handle == NULL)
    {
        return;
    }

    free(handle);
}

int did_serialize(did_handle handle, char *buffer, size_t buff_len)
{
    did_context_t *context = (did_context_t *)handle;
    cJSON *did_root = NULL;
    cJSON *key_root = NULL;
    char *privkey_base64 = NULL;
    char *pubkey_base64 = NULL;
    int privkey_base64_len = 0;
    int pubkey_base64_len = 0;
    int result = -1;
    char *json_str = NULL;

    did_root = cJSON_CreateObject();
    if (cJSON_AddStringToObject(did_root, "did", context->did) == NULL)
    {
        goto RET;
    }

    if (cJSON_AddStringToObject(did_root, "algo", context->algo) == NULL)
    {
        goto RET;
    }

    privkey_base64_len = BASE64_ENCODE_OUT_SIZE(context->key_pair.priv_len);
    pubkey_base64_len = BASE64_ENCODE_OUT_SIZE(context->key_pair.pubkey_len);

    privkey_base64 = (char *)malloc(privkey_base64_len);
    if (privkey_base64 == NULL)
    {
        goto RET;
    }
    base64_encode(context->key_pair.priv, context->key_pair.priv_len, privkey_base64);

    pubkey_base64 = (char *)malloc(pubkey_base64_len);
    if (pubkey_base64 == NULL)
    {
        goto RET;
    }
    base64_encode(context->key_pair.pubkey, context->key_pair.pubkey_len, pubkey_base64);

    key_root = cJSON_AddObjectToObject(did_root, "key_pair");
    if (key_root == NULL)
    {
        goto RET;
    }
    if (cJSON_AddStringToObject(key_root, "priv", privkey_base64) == NULL)
    {
        goto RET;
    }

    if (cJSON_AddStringToObject(key_root, "pub", pubkey_base64) == NULL)
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

did_handle did_deserialize(const char *buffer)
{
    did_context_t *context = (did_context_t *)malloc(sizeof(did_context_t));
    cJSON *did_json = NULL;
    cJSON *key_pair_item = NULL;
    cJSON *item = NULL;
    int data_length = 0;
    unsigned char key_buffer[2048] = {0};
    char *key_base64_str = NULL;
    memset(context, 0, sizeof(did_context_t));

    did_json = cJSON_Parse(buffer);
    if (did_json == NULL)
    {
        goto ERR;
    }

    item = cJSON_GetObjectItem(did_json, "did");
    if (item == NULL)
    {
        goto ERR;
    }

    strcpy(context->did, cJSON_GetStringValue(item));

    item = cJSON_GetObjectItem(did_json, "algo");
    if (item == NULL)
    {
        goto ERR;
    }

    strcpy(context->algo, cJSON_GetStringValue(item));

    key_pair_item = cJSON_GetObjectItem(did_json, "key_pair");
    if (key_pair_item == NULL)
    {
        goto ERR;
    }

    key_base64_str = cJSON_GetStringValue(cJSON_GetObjectItem(key_pair_item, "pub"));
    data_length = base64_decode(key_base64_str, strlen(key_base64_str), key_buffer);

    context->key_pair.pubkey_len = data_length;
    memcpy(context->key_pair.pubkey, key_buffer, data_length);

    key_base64_str = cJSON_GetStringValue(cJSON_GetObjectItem(key_pair_item, "priv"));
    data_length = base64_decode(key_base64_str, strlen(key_base64_str), key_buffer);

    context->key_pair.priv_len = data_length;
    memcpy(context->key_pair.priv, key_buffer, data_length);

    if (did_json != NULL)
    {
        cJSON_Delete(did_json);
    }

    return context;
ERR:
    if (did_json != NULL)
    {
        cJSON_Delete(did_json);
    }

    if (context != NULL)
    {
        free(context);
    }

    return NULL;
}

int did_sign_hash(did_handle handle, const unsigned char *hash, char *out, size_t out_len)
{
    did_context_t *context = (did_context_t *)handle;
    return key_sign_hash(&context->key_pair, context->algo, hash, out, out_len);
}

int did_verify_hash(did_key_t *did_key, const unsigned char *hash, unsigned char *sign, size_t sign_len)
{
    if (strcmp(did_key->type, "EcdsaSecp256k1VerificationKey2019") == 0)
    {
        return key_verify_hash_with_address(did_key->publicKeyAddress, "secp256k1", hash, sign, sign_len);
    }
    else
    {
        return -1;
    }
}

int did_verify_hash_with_pubkey(did_key_t* did_key, const unsigned char* pubkey, const unsigned char* hash, unsigned char* sign, size_t sign_len)
{
    if (strcmp(did_key->type, "EcdsaSecp256k1VerificationKey2019") == 0)
    {
        return key_verify_hash_with_pubkey(pubkey, did_key->publicKeyAddress,"secp256k1", hash, sign, sign_len);
    }
    else
    {
        return -1;
    }
}

int nodid_verify_hash_with_pubkey(did_key_t* did_key, const unsigned char* pubkey, const unsigned char* hash, unsigned char* sign, size_t sign_len)
{
    if (strcmp(did_key->type, "EcdsaSecp256k1VerificationKey2019") == 0)
    {
        return key_verify_hash_with_noaddress(pubkey, "secp256k1", hash, sign, sign_len);
    }
    else
    {
        return -1;
    }
}

int did_get_pubkey(did_handle handle, unsigned char* buffer, size_t buff_len) {
    did_context_t *context = (did_context_t *)handle;
    memcpy(buffer, context->key_pair.pubkey, context->key_pair.pubkey_len);
    return context->key_pair.pubkey_len;
}

did_meta_t* did_to_did_meta(did_handle handle)
{
    did_context_t *context = (did_context_t *)handle;
    did_meta_t *meta = (did_meta_t *)malloc(sizeof(did_meta_t));

    strcpy(meta->did, context->did);
    strcpy(meta->controller, context->did);

    if (strcmp(context->algo, "secp256k1") == 0)
    {
        // Only support one key in did document
        meta->did_keys = (did_key_t *)malloc(sizeof(did_key_t));
        strcpy(meta->did_keys->type, "EcdsaSecp256k1VerificationKey2019");
        strcpy(meta->did_keys->relationship, "authentication");
        strcpy(meta->did_keys->id, "keys-1");
        strcpy(meta->did_keys->controller, context->did);

        unsigned char pubKeyHex[45] = {0};
        did_export_pubkey(handle, pubKeyHex);
        strcpy(meta->did_keys->publicKeyAddress, pubKeyHex);

        meta->did_services = NULL;

        return meta;
    }
    else
    {
        free(meta);
        return NULL;
    }
}

void did_meta_destroy(did_meta_t *meta)
{
    if (meta->did_keys != NULL)
    {
        free(meta->did_keys);
    }

    if (meta->did_services != NULL)
    {
        free(meta->did_services);
    }

    free(meta);
}

int did_export_prikey(did_handle did, char *out)
{
    if (did == NULL)
    {
        return -1;
    }

    did_context_t *context = (did_context_t *)did;

    char data[321] = {0};
    strcat(data, context->algo);
    strcat(data, ".");

    char pHex[32 * 8 + 1] = {0};
    memset(pHex, 0, 32 * 8 + 1);

    int i = 0;
    for (i = 0; i < context->key_pair.priv_len; i++)
    {
        char strTemp[9] = {0};
        int j = sprintf(strTemp, "%02x", context->key_pair.priv[i]);
        strcat(pHex, strTemp);
        // printf("\n strTemp:%s",strTemp);
    }

    strcat(data, pHex);
    memcpy(out, data, strlen(data));
    return 0;
}

int did_export_pubkey(did_handle did, char *eth_address)
{
    if (did == NULL)
    {
        return -1;
    }

    did_context_t *context = (did_context_t *)did;

    key_to_address(&context->key_pair, context->algo, eth_address);

    return 0;
}

did_handle did_import_privkey(const char *data)
{
    did_context_t *handle = (did_context_t *)malloc(sizeof(did_context_t));
    if (handle == NULL)
    {
        return NULL;
    }
    memset(handle, 0, sizeof(did_context_t));

    char *p = data;
    char algo[64] = {0};
    char priv_key[128] = {0};
    size_t algo_len = 0;
    size_t priv_key_len = 0;

    while (*p != '.' && algo_len < strlen(data))
    {
        algo_len += 1;
        ++p;
    }

    memcpy(priv_key, data + algo_len + 1, strlen(data) - algo_len);
    memcpy(algo, data, algo_len);

    char bin_key[64] = {0};
    size_t bin_key_len = 32;

    int i = 0;
    char* pos = priv_key;
    for (i = 0; i < bin_key_len; i++)
    {
        sscanf(pos, "%2hhx", &bin_key[i]);
        pos += 2;
    }

    import_key_pair(algo, 64, bin_key, &handle->key_pair);
    strcpy(handle->algo, algo);

    char hash[32] = {0};
    size_t base58_len = 64;
    
    SHA3_CTX sha3_ctx;
    keccak_init(&sha3_ctx);
    keccak_update(&sha3_ctx, handle->key_pair.pubkey, handle->key_pair.pubkey_len);
    keccak_final(&sha3_ctx, hash);

    b58_encode(hash, 32, handle->did, &base58_len);
    return handle;
}
