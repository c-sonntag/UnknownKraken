#ifndef UNKNOWNECHO_BYTE_WRITER_H
#define UNKNOWNECHO_BYTE_WRITER_H

#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_stream_struct.h>

#include <stddef.h>

bool ue_byte_writer_append_bytes(ue_byte_stream *stream, unsigned char *bytes, size_t bytes_len);

bool ue_byte_writer_append_string(ue_byte_stream *stream, char *string);

bool ue_byte_writer_append_byte(ue_byte_stream *stream, unsigned char byte);

bool ue_byte_writer_append_int(ue_byte_stream *stream, int n);

bool ue_byte_writer_append_long(ue_byte_stream *stream, long n);

bool ue_byte_writer_append_size_t(ue_byte_stream *stream, size_t n);

#endif
