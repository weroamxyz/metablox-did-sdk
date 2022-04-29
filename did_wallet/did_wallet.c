#include "did_wallet.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "leveldb/c.h"
#include "common/aes.h"
#include "cJSON/cJSON.h"

#define MAX_PATH (260)
#define DID_KEY_PREFIX "did_"

typedef struct wallet_context_tag
{
    char path[MAX_PATH];
    leveldb_t *db;
} wallet_context_t;

wallet_handle wallet_handle_create(const char *name, const char *path)
{
    leveldb_options_t *options = NULL;
    char *error = NULL;
    wallet_context_t *context = (wallet_context_t *)malloc(sizeof(wallet_context_t));
    if (context == NULL)
    {
        return NULL;
    }

    strcpy(context->path, path);

    options = leveldb_options_create();
    if (options == NULL)
    {
        free(context);
        return NULL;
    }

    leveldb_options_set_create_if_missing(options, 1);
    context->db = leveldb_open(options, path, &error);
    if (context->db == NULL)
    {
        leveldb_options_destroy(options);
        free(context);
        return NULL;
    }

    leveldb_options_destroy(options);
    return context;
}

void wallet_handle_destroy(wallet_handle handle)
{
    wallet_context_t *context = (wallet_context_t *)handle;
    if (context->db != NULL)
    {
        leveldb_close(context->db);
    }

    context->db = NULL;

    free(context);
}

int wallet_store_did(wallet_handle wallet, did_handle did, const char *name, const char *password)
{
    wallet_context_t *context = (wallet_context_t *)wallet;
    int len = did_serialize(did, NULL, 0);
    if (len <= 0)
    {
        return len;
    }

    // Padding buffer with 0 for aes encrypt
    len = (len + 15) / 16 * 16;
    char *buffer = (char *)malloc(len);
    char key[128] = {0};
    char *error = NULL;
    struct AES_ctx aes_ctx;

    AES_init_ctx(&aes_ctx, (const uint8_t *)password);
    AES_ctx_set_iv(&aes_ctx, (const uint8_t *)password);
    memset(buffer, 0, len);
    did_serialize(did, buffer, len);

    AES_CBC_encrypt_buffer(&aes_ctx, (unsigned char *)buffer, len);

    sprintf(key, "%s%s", DID_KEY_PREFIX, name);

    leveldb_writeoptions_t *options = leveldb_writeoptions_create();

    leveldb_put(context->db, options, key, strlen(key), buffer, len, &error);

    free(buffer);
    leveldb_writeoptions_destroy(options);

    return len;
}

did_handle wallet_load_did(wallet_handle wallet, const char *name, const char *password)
{
    wallet_context_t *context = (wallet_context_t *)wallet;
    char key[128] = {0};
    char *error = NULL;
    size_t len = 0;
    struct AES_ctx aes_ctx;

    AES_init_ctx(&aes_ctx, (const unsigned char *)password);
    AES_ctx_set_iv(&aes_ctx, (const unsigned char *)password);

    sprintf(key, "%s%s", DID_KEY_PREFIX, name);

    leveldb_readoptions_t *options = leveldb_readoptions_create();
    char *data = leveldb_get(context->db, options, key, strlen(key), &len, &error);

    if (data == NULL)
    {
        free(options);
        return NULL;
    }

    AES_CBC_decrypt_buffer(&aes_ctx, (unsigned char *)data, len);

    // Padding with 0 has no effect on parsing as json
    did_handle did = did_deserialize(data);

    leveldb_readoptions_destroy(options);
    free(data);
    return did;
}

int wallet_change_name(wallet_handle wallet, const char *oldname, const char *newname)
{
    wallet_context_t *context = (wallet_context_t *)wallet;

    leveldb_writeoptions_t *write_options = leveldb_writeoptions_create();
    leveldb_readoptions_t *read_options = leveldb_readoptions_create();
    if (write_options == NULL || read_options == NULL)
    {
        return -1;
    }

    char old_key[128] = {0};
    char *error = NULL;
    sprintf(old_key, "%s%s", DID_KEY_PREFIX, oldname);

    size_t len = 0;
    char *data = leveldb_get(context->db, read_options, old_key, strlen(old_key), &len, &error);
    if (data == NULL)
    {
        leveldb_writeoptions_destroy(write_options);
        leveldb_readoptions_destroy(read_options);
        return -1;
    }

    char new_key[128] = {0};
    sprintf(new_key, "%s%s", DID_KEY_PREFIX, newname);
    leveldb_put(context->db, write_options, new_key, strlen(new_key), data, len, &error);

    leveldb_delete(context->db, write_options, old_key, strlen(old_key), &error);
    if (error != NULL)
    {
        leveldb_writeoptions_destroy(write_options);
        leveldb_readoptions_destroy(read_options);
        return -1;
    }

    leveldb_writeoptions_destroy(write_options);
    leveldb_readoptions_destroy(read_options);

    return 0;
}

int wallet_change_password(wallet_handle wallet, const char *name, const char *oldpassword, const char *newpassword)
{
    wallet_context_t *context = (wallet_context_t *)wallet;

    struct AES_ctx old_aes_ctx, new_aes_ctx;

    AES_init_ctx(&old_aes_ctx, (const uint8_t *)oldpassword);
    AES_ctx_set_iv(&old_aes_ctx, (const uint8_t *)oldpassword);

    AES_init_ctx(&new_aes_ctx, (const uint8_t *)newpassword);
    AES_ctx_set_iv(&new_aes_ctx, (const uint8_t *)newpassword);

    char key[128] = {0};
    char *error = NULL;
    size_t len = 0;
    sprintf(key, "%s%s", DID_KEY_PREFIX, name);
    leveldb_readoptions_t *options = leveldb_readoptions_create();
    char *data = leveldb_get(context->db, options, key, strlen(key), &len, &error);
    if (data == NULL)
    {
        leveldb_readoptions_destroy(options);
        return -1;
    }

    AES_CBC_decrypt_buffer(&old_aes_ctx, (unsigned char *)data, len);

    // Padding with 0 has no effect on parsing as json
    did_handle did1 = did_deserialize(data);
    if (did1 == NULL)
    {
        leveldb_readoptions_destroy(options);
        return -1;
    }

    did_handle did = wallet_load_did(wallet, name, oldpassword);
    if (did == NULL)
    {
        leveldb_readoptions_destroy(options);
        return -1;
    }
    wallet_store_did(wallet, did, name, newpassword);

    leveldb_readoptions_destroy(options);
    return 0;
}

int wallet_get_namelist(wallet_handle wallet, wallet_did_nl *data)
{
    data->count = 0;
    data->names = NULL;

    wallet_context_t *context = (wallet_context_t *)wallet;
    leveldb_readoptions_t *options = NULL;
    options = leveldb_readoptions_create();
    if (options == NULL)
    {
        return -1;
    }

    leveldb_iterator_t *point = leveldb_create_iterator(context->db, options);
    if (point == NULL)
    {
        leveldb_readoptions_destroy(options);
        return -1;
    }

    size_t keylen = 0;
    for (leveldb_iter_seek(point, "did_", strlen("did_")); leveldb_iter_valid(point) && (strcmp(leveldb_iter_key(point, &keylen), "did_") > 0); leveldb_iter_next(point))
    {
        data->count += 1;
    }
    printf("\n data count:%d", data->count);

    data->names = (char **)malloc(sizeof(char *) * data->count);
    int i = 0;
    for (i = 0; i < data->count; i++)
    {
        data->names[i] = NULL;
    }
    int j = 0;
    for (leveldb_iter_seek(point, "did_", strlen("did_")); leveldb_iter_valid(point); leveldb_iter_next(point))
    {
        char *key = leveldb_iter_key(point, &keylen);

        char *pox = key + 3;
        if (*pox != '_')
        {
            break;
        }

        data->names[j] = (char *)malloc(keylen);
        memset(data->names[j], 0, keylen);
        memcpy(data->names[j], key + 4, keylen - 4);
        ++j;
    }

    leveldb_readoptions_destroy(options);
    leveldb_iter_destroy(point);
    return 0;
}

void did_wallet_free_namelist(wallet_did_nl *namelist)
{
    int i = 0;
    for (i = 0; i < namelist->count; i++)
    {
        free(namelist->names[i]);
    }
    free(namelist->names);
}