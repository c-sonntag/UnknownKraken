#ifndef UNKNOWNECHO_BASE64_DECODE_IMPL_H
#define UNKNOWNECHO_BASE64_DECODE_IMPL_H

#include <stddef.h>

unsigned char *ue_base64_decode_impl(const unsigned char *src, size_t len, size_t *out_len);

#endif
