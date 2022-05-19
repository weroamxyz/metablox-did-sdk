#include "did_register.h"
#include "string.h"
#include "curl/curl.h"
#include "conf/did_conf.h"
#include "cJSON/cJSON.h"
#include "common/base64.h"
#include "keccak256/keccak256.h"

typedef struct register_context_tag
{
    char url[MAX_URL_LEN];
} register_context_t;

static char *encode_did_meta(did_meta_t *meta);
static char *build_request_body(did_handle did);

register_handle register_create(const char *url)
{
    register_context_t *context = (register_context_t *)malloc(sizeof(register_context_t));
    strcpy(context->url, url);

    return context;
}

void register_destroy(register_handle handle)
{
    free(handle);
}

int register_submit(register_handle handle, did_handle did)
{
    register_context_t *context = (register_context_t *)handle;
    CURL *curl = NULL;
    CURLcode res;
    int result = 0;
    char *key_text = NULL;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if (curl == NULL)
    {
        goto RET;
    }

    curl_easy_setopt(curl, CURLOPT_URL, context->url);
    key_text = build_request_body(did);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, key_text);

    res = curl_easy_perform(curl);
    result = 1;

RET:
    if (key_text != NULL)
    {
        free(key_text);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return result;
}
/*
    unsigned char  id[MAX_DID_DOC_ELEMENT_ID_LEN];
    unsigned char  type[MAX_TYPE_LEN];
    unsigned char  controller[MAX_DID_STR_LEN];
    unsigned char  publicKeyHex[MAX_KEY_PUBKEY_BASE58_LEN];
    unsigned char  relationship[MAX_RELATIONSHIP_LEN];
*/

char *encode_did_meta(did_meta_t *meta)
{
    cJSON *did_root = cJSON_CreateObject();
    cJSON *key_root = NULL;
    cJSON *key_item = NULL;
    char *json_str = NULL;

    if (cJSON_AddStringToObject(did_root, "did", meta->did) == NULL)
    {
        goto ERR;
    }

    if (cJSON_AddStringToObject(did_root, "controller", meta->controller) == NULL)
    {
        goto ERR;
    }

    key_root = cJSON_AddArrayToObject(did_root, "keys");
    if (key_root == NULL)
    {
        goto ERR;
    }

    key_item = cJSON_CreateObject();
    if (cJSON_AddStringToObject(key_item, "id", meta->did_keys->id) == NULL)
    {
        goto ERR;
    }

    if (cJSON_AddStringToObject(key_item, "type", meta->did_keys->type) == NULL)
    {
        goto ERR;
    }

    if (cJSON_AddStringToObject(key_item, "controller", meta->did_keys->controller) == NULL)
    {
        goto ERR;
    }

    if (cJSON_AddStringToObject(key_item, "publicKeyAddress", meta->did_keys->publicKeyAddress) == NULL)
    {
        goto ERR;
    }

    if (cJSON_AddStringToObject(key_item, "relationship", meta->did_keys->relationship) == NULL)
    {
        goto ERR;
    }

    cJSON_AddItemToArray(key_root, key_item);
    key_item = NULL;

    json_str = cJSON_Print(did_root);
    cJSON_Delete(did_root);
    return json_str;
ERR:
    if (key_item != NULL)
    {
        cJSON_Delete(key_item);
    }

    if (did_root != NULL)
    {
        cJSON_Delete(did_root);
    }

    return NULL;
}

char *build_request_body(did_handle did)
{
    did_meta_t *meta = did_to_did_meta(did);
    char *did_text = NULL;
    unsigned char signature[64] = {0};
    unsigned char sig_base64[128] = {0};
    cJSON *request_root = NULL;
    char *request_text = NULL;
    char hash[32] = {0};

    if (meta == NULL)
    {
        goto ERR;
    }

    did_text = encode_did_meta(meta);
    if (did_text == NULL)
    {
        goto ERR;
    }

    SHA3_CTX sha3_ctx;
    keccak_init(&sha3_ctx);
    keccak_update(&sha3_ctx, "HelloWorld", strlen("HelloWorld"));
    keccak_final(&sha3_ctx, hash);
    
    if (did_sign_hash(did, hash, signature, 64) != 64)
    {
        goto ERR;
    }

    base64_encode(signature, 64, sig_base64);

    request_root = cJSON_CreateObject();
    if (request_root == NULL)
    {
        goto ERR;
    }

    if (cJSON_AddStringToObject(request_root, "did", did_text) == NULL)
    {
        goto ERR;
    }

    if (cJSON_AddStringToObject(request_root, "signature", sig_base64) == NULL)
    {
        goto ERR;
    }

    request_text = cJSON_Print(request_root);
    cJSON_Delete(request_root);
    free(did_text);
    did_meta_destroy(meta);

    return request_text;

ERR:
    if (request_root == NULL)
    {
        cJSON_Delete(request_root);
    }

    if (did_text != NULL)
    {
        free(did_text);
    }

    if (meta != NULL)
    {
        did_meta_destroy(meta);
    }

    return NULL;
}
