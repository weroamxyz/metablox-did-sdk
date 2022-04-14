#include "did_wallet.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "leveldb/c.h"
#include "common/aes.h"

#define  MAX_PATH            (260)
#define  DID_KEY_PREFIX      "did_"


typedef struct wallet_context_tag {
    char  path[MAX_PATH];
    leveldb_t* db;
} wallet_context_t;

wallet_handle wallet_handle_create(const char* name, const char* path) 
{
    leveldb_options_t* options = NULL;
    char* error = NULL;
    wallet_context_t* context = (wallet_context_t*)malloc(sizeof(wallet_context_t));
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
    wallet_context_t* context = (wallet_context_t*)handle;
    if (context->db != NULL) 
    {
        leveldb_close(context->db);
    }

    context->db = NULL;

    free(context);
}

int wallet_store_did(wallet_handle wallet, did_handle did, const char* name, const char* password) 
{
    wallet_context_t* context = (wallet_context_t*)wallet;
    int len = did_serialize(did, NULL, 0);
    if (len <= 0) {
        return len;
    }
    
    // Padding buffer with 0 for aes encrypt
    len = (len + 15) / 16  * 16;
    char* buffer = (char*)malloc(len);
    char key[128] = {0};
    char* error = NULL;
    struct AES_ctx aes_ctx;

    AES_init_ctx(&aes_ctx, (const uint8_t*)password);
    AES_ctx_set_iv(&aes_ctx, (const uint8_t*)password);
    memset(buffer, 0, len);
    did_serialize(did, buffer, len);
 
    AES_CBC_encrypt_buffer(&aes_ctx, (unsigned char*)buffer, len);

    sprintf(key, "%s%s", DID_KEY_PREFIX, name);
    
    leveldb_writeoptions_t*  options = leveldb_writeoptions_create();
    
    leveldb_put(context->db, options, key, strlen(key), buffer, len, &error);
    
    free(buffer);
    leveldb_writeoptions_destroy(options);

    return len;
}

did_handle wallet_load_did(wallet_handle wallet, const char* name, const char* password) 
{
    wallet_context_t* context = (wallet_context_t*)wallet;
    char key[128] = {0};
    char* error = NULL;
    size_t len = 0;
    struct AES_ctx aes_ctx;

    AES_init_ctx(&aes_ctx, (const unsigned char*)password);
    AES_ctx_set_iv(&aes_ctx, (const unsigned char*)password);
    
    sprintf(key, "%s%s", DID_KEY_PREFIX, name);

    leveldb_readoptions_t*  options = leveldb_readoptions_create();
    char* data = leveldb_get(context->db, options, key, strlen(key), &len, &error);

    if (data == NULL) {
        free(options);
        return NULL;
    }
    
    AES_CBC_decrypt_buffer(&aes_ctx, (unsigned char*)data, len);

    //Padding with 0 has no effect on parsing as json
    did_handle did = did_deserialize(data);

    leveldb_readoptions_destroy(options);
    free(data);
    return did;
}

//export did
void wallet_export_did(wallet_handle wallet, const char *name, char *path)
{
  // 1. get did data
  wallet_context_t* context = (wallet_context_t*)wallet;
  char key[128] = {0};
  sprintf(key, "%s%s", DID_KEY_PREFIX, name);
  size_t len = 0;
  char* read_error = NULL;
  leveldb_readoptions_t*  read_options = leveldb_readoptions_create();
  char* data = leveldb_get(context->db, read_options, key, strlen(key), &len, &read_error);

  // 2. create new db
  // call once create once
  char buffer[2048] = {0};
  char *error = NULL;
  leveldb_options_t *options = NULL;
  options = leveldb_options_create();
  if (options == NULL)
  {
    free(data);
    free(read_error);
    leveldb_options_destroy(options);
    leveldb_readoptions_destroy(read_options);
    return;
  }
  leveldb_options_set_create_if_missing(options, 1);
  leveldb_t *db = leveldb_open(options, path, &error); // export path
  if (db == NULL)
  {
    free(error);
    free(data);
    free(read_error);
    leveldb_options_destroy(options);
    leveldb_readoptions_destroy(read_options);
    leveldb_close(db);
    return;
  }

  // 3. did to path
  leveldb_writeoptions_t *w_options = leveldb_writeoptions_create();
  leveldb_put(db, w_options, key, strlen(key), data, len, &error);
  // 4. destroy
  free(error);
  free(data);
  free(read_error);
  leveldb_options_destroy(options);
  leveldb_writeoptions_destroy(w_options);
  leveldb_readoptions_destroy(read_options);
  leveldb_close(db);
}

void wallet_import_did(wallet_handle wallet, char *path, const char *name, const char *password)
{
  // 1. create db
  leveldb_options_t *options = NULL;
  char *error = NULL;
  options = leveldb_options_create();
  if (options == NULL)
  {
    leveldb_options_destroy(options);
    return;
  }
  leveldb_options_set_create_if_missing(options, 1);
  leveldb_t *db = leveldb_open(options, path, &error); // export path
  if (db == NULL)
  {
    free(error);
    leveldb_options_destroy(options);
    return;
  }

  // 2. read did
  char key[128] = {0};
  size_t len = 0;
  sprintf(key, "%s%s", DID_KEY_PREFIX, name);
  leveldb_readoptions_t *r_options = leveldb_readoptions_create();
  char *data = leveldb_get(db, r_options, key, strlen(key), &len, &error);
  if (data == NULL)
  {
    free(error);
    leveldb_readoptions_destroy(r_options);
    leveldb_options_destroy(options);
    leveldb_close(db);
    return NULL;
  }

  //3. store did
  did_handle did = did_deserialize(data);
  wallet_store_did(wallet, did, name, password);

  // 4. destroy
  leveldb_options_destroy(options);
  leveldb_readoptions_destroy(r_options);
  leveldb_close(db);
  free(data);
}