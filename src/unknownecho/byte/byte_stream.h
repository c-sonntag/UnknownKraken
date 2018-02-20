#ifndef UNKNOWNECHO_BYTE_STREAM_H
#define UNKNOWNECHO_BYTE_STREAM_H

#include <unknownecho/byte/byte_stream_struct.h>
#include <unknownecho/bool.h>

#include <stddef.h>

ue_byte_stream *ue_byte_stream_create();

ue_byte_stream *ue_byte_stream_create_limit(size_t limit);

void ue_byte_stream_clean_up(ue_byte_stream *stream);

void ue_byte_stream_destroy(ue_byte_stream *stream);

unsigned char *ue_byte_stream_get_data(ue_byte_stream *stream);

size_t ue_byte_stream_get_position(ue_byte_stream *stream);

bool ue_byte_stream_set_position(ue_byte_stream *stream, size_t position);

size_t ue_byte_stream_get_size(ue_byte_stream *stream);

void ue_byte_stream_print(ue_byte_stream *stream);

#endif
