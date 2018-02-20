#ifndef UNKNOWNECHO_BYTE_READER_H
#define UNKNOWNECHO_BYTE_READER_H

#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_stream_struct.h>

#include <stddef.h>

bool ue_byte_read_next_int(ue_byte_stream *stream, int *n);

bool ue_byte_read_next_bytes(ue_byte_stream *stream, unsigned char **bytes, size_t len);

#endif
