#ifndef __BASE58_H__
#define __BASE58_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int b58_decode(void *bin, size_t *binsz, const char *b58, size_t b58sz);
int b58_encode(char *b58, size_t *b58sz, const void *bin, size_t binsz);

#ifdef __cplusplus
}
#endif

#endif