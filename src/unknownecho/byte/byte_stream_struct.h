#ifndef UNKNOWNECHO_BYTE_STREAM_STRUCT_H
#define UNKNOWNECHO_BYTE_STREAM_STRUCT_H

#include <stddef.h>

typedef struct {
	unsigned char *bytes;
	size_t limit;
	size_t position;
	size_t size;
} ue_byte_stream;

#endif
