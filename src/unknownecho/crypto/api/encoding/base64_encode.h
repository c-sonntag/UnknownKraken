#ifndef UNKNOWNECHO_BASE64_ENCODE_H
#define UNKNOWNECHO_BASE64_ENCODE_H

#include <stddef.h>

unsigned char *ue_base64_encode(const unsigned char *src, size_t len, size_t *out_len);

#endif
