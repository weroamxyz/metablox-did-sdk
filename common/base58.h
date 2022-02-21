#ifndef __BASE58_H__
#define __BASE58_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int b58_decode(const char *b58, size_t b58sz, void *bin, size_t *binsz);
int b58_encode(const void *bin, size_t binsz, char *b58, size_t *b58sz);

#ifdef __cplusplus
}
#endif

#endif