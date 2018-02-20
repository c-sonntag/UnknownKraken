#ifndef UNKNOWNECHO_BASE64_DECODE_H
#define UNKNOWNECHO_BASE64_DECODE_H

#include <stddef.h>

unsigned char *ue_base64_decode(const unsigned char *src, size_t len, size_t *out_len);

#endif
