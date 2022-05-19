#ifndef __BASE64_H__
#define __BASE64_H__

#include "stdlib.h"

#ifdef __cplusplus 
extern "C" {
#endif 

#define BASE64_ENCODE_OUT_SIZE(s) ((unsigned int)((((s) + 2) / 3) * 4 + 1))
#define BASE64_DECODE_OUT_SIZE(s) ((unsigned int)(((s) / 4) * 3))

int base64_encode(const unsigned char *src, size_t len, char *out);
int base64_decode(const char *src, size_t len, unsigned char* out);

int base64_urlraw_encode(const unsigned char *src, size_t len, char *out);
int base64_urlraw_decode(const char *src, size_t len, unsigned char* out);

#ifdef __cplusplus 
}
#endif 
#endif /* __BASE64_H__  */
