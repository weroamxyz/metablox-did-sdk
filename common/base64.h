#ifndef __BASE64_H__
#define __BASE64_H__

#include "stdlib.h"

#ifdef __cplusplus 
extern "C" {
#endif 

int base64_encode(const unsigned char *src, size_t len, unsigned char *out);
int base64_decode(const unsigned char *src, size_t len, unsigned char* out);

#ifdef __cplusplus 
}
#endif 
#endif /* __BASE64_H__  */