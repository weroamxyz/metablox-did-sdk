#include "did.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "cJSON/cJSON.h"
#include "common/base64.h"
#include "common/base58.h"
#include "common/sha256.h"

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

    char hash[32] = {0};
    size_t base58_len = 64;
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, handle->key_pair.pubkey, handle->key_pair.pubkey_len);
    sha256_final(&ctx, hash);

    b58_encode(hash, 32, handle->did, &base58_len);
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

int did_sign(did_handle handle, const char *msg, size_t msg_len, char *out, size_t out_len)
{
    did_context_t *context = (did_context_t *)handle;
    return key_sign(&context->key_pair, context->algo, msg, msg_len, out, out_len);
}

int did_verify(did_key_t *did_key, const char *msg, size_t msg_len, const char *sign, size_t sign_len)
{
    if (strcmp(did_key->type, "EcdsaSecp256k1VerificationKey2019") == 0)
    {
        key_pair_t key_pair;
        key_pair.pubkey_len = 64;
        size_t pubkey_len = 64;
        int result = b58_decode(did_key->publicKeyBase58, strlen(did_key->publicKeyBase58), key_pair.pubkey, &pubkey_len);
        if (result == 0)
        {
            return result;
        }
        key_pair.pubkey_len = (unsigned short)pubkey_len;

        return key_verify(&key_pair, "secp256k1", msg, msg_len, sign, sign_len);
    }
    else
    {
        return 0;
    }
}

did_meta_t *did_to_did_meta(did_handle handle)
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
        size_t base58_len = MAX_KEY_PUBKEY_BASE58_LEN;
        b58_encode(context->key_pair.pubkey, context->key_pair.pubkey_len, meta->did_keys->publicKeyBase58, &base58_len);

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
    }

    strcat(data, pHex);
    memcpy(out, data, strlen(data));
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
    for (i = 0; i < bin_key_len; i++)
    {
        char temp[2] = {0};
        memcpy(temp, priv_key + 2 * i, 2);

        char tmp = 0;
        tmp = HexCharToBinBinChar(temp[0]);
        tmp <<= 4;
        tmp |= HexCharToBinBinChar(temp[1]);
        memcpy(&bin_key[i], &tmp, 1);
    }

    import_key_pair(algo, 64, bin_key, &handle->key_pair);
    strcpy(handle->algo, algo);

    char hash[32] = {0};
    size_t base58_len = 64;
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, handle->key_pair.pubkey, handle->key_pair.pubkey_len);
    sha256_final(&ctx, hash);

    b58_encode(hash, 32, handle->did, &base58_len);
    return handle;
}

char HexCharToBinBinChar(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'z')
        return c - 'a' + 10;
    else if (c >= 'A' && c <= 'Z')
        return c - 'A' + 10;
    return 0xff;
}