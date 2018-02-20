#ifndef UNKNOWNECHO_BYTE_SPLIT_H
#define UNKNOWNECHO_BYTE_SPLIT_H

#include <unknownecho/byte/byte_stream_struct.h>

#include <stddef.h>

unsigned char **ue_byte_split(unsigned char *bytes, size_t bytes_len, unsigned char *delimiter, size_t delimiter_len, size_t *count, size_t **sizes);

#endif
