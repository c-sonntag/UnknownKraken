/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/alloc.h>
#include <ei/ei.h>

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

bool ue_byte_writer_append_bytes(ue_byte_stream *stream, unsigned char *bytes, long bytes_len) {
	ei_check_parameter_or_return(stream);
    ei_check_parameter_or_return(bytes);
    ei_check_parameter_or_return(bytes_len > 0 && bytes_len != 18446744073709551615UL);

    if ((bytes_len + stream->position) > stream->size) {
        ue_safe_realloc(stream->bytes, unsigned char, stream->size, bytes_len + stream->size);
        stream->size += bytes_len;
    }

    memcpy(stream->bytes + stream->position, bytes, bytes_len);

    stream->position += bytes_len;

    return true;
}

bool ue_byte_writer_append_string(ue_byte_stream *stream, const char *string) {
    long string_len;

    ei_check_parameter_or_return(stream);
    ei_check_parameter_or_return(string);

    string_len = strlen(string);

    ei_check_parameter_or_return(string_len > 0 && string_len != 18446744073709551615UL);

    if ((string_len + stream->position) > stream->size) {
        ue_safe_realloc(stream->bytes, unsigned char, stream->size, string_len + stream->size);
        stream->size += string_len;
    }

    memcpy(stream->bytes + stream->position, string, string_len);

    stream->position += string_len;

    return true;
}

bool ue_byte_writer_append_byte(ue_byte_stream *stream, unsigned char byte) {
	ei_check_parameter_or_return(stream);

    if ((1 + stream->position) > stream->size) {
        ue_safe_realloc(stream->bytes, unsigned char, stream->size, 1 + stream->size);
        stream->size += 1;
    }

	stream->bytes[stream->position++] = byte;

    return true;
}

bool ue_byte_writer_append_int(ue_byte_stream *stream, int n) {
	ei_check_parameter_or_return(stream);

    if ((4 + stream->position) > stream->size) {
        ue_safe_realloc(stream->bytes, unsigned char, stream->size, 4 + stream->size);
        stream->size += 4;
    }

    stream->bytes[stream->position++] = (n >> 24) & 0xFF;
    stream->bytes[stream->position++] = (n >> 16) & 0xFF;
    stream->bytes[stream->position++] = (n >> 8) & 0xFF;
    stream->bytes[stream->position++] = n & 0xFF;

    return true;
}

bool ue_byte_writer_append_long(ue_byte_stream *stream, long int n) {
   ei_check_parameter_or_return(stream);

    if ((8 + stream->position) > stream->size) {
        ue_safe_realloc(stream->bytes, unsigned char, stream->size, 8 + stream->size);
        stream->size += 8;
    }

    stream->bytes[stream->position++] = ((uint64_t)n >> 56) & 0xFF;
    stream->bytes[stream->position++] = ((uint64_t)n >> 48) & 0xFF;
    stream->bytes[stream->position++] = ((uint64_t)n >> 40) & 0xFF;
    stream->bytes[stream->position++] = ((uint64_t)n >> 32) & 0xFF;
    stream->bytes[stream->position++] = ((uint64_t)n >> 24) & 0xFF;
    stream->bytes[stream->position++] = ((uint64_t)n >> 16) & 0xFF;
    stream->bytes[stream->position++] = ((uint64_t)n >> 8) & 0xFF;
    stream->bytes[stream->position++] = (uint64_t)n & 0xFF;

    return true;
}

bool ue_byte_writer_append_stream(ue_byte_stream *stream, ue_byte_stream *to_copy) {
    ei_check_parameter_or_return(stream);
    ei_check_parameter_or_return(to_copy);

    if (ue_byte_stream_is_empty(to_copy)) {
        ei_stacktrace_push_msg("Specified stream to copy is empty");
        return false;
    }

    /* Set the virtual cursor of the byte stream to the begining for safety */

    if (!ue_byte_writer_append_int(stream, (int)ue_byte_stream_get_size(to_copy))) {
        ei_stacktrace_push_msg("Failed to write data size to destination stream");
        return false;
    }

    if (!ue_byte_writer_append_bytes(stream, ue_byte_stream_get_data(to_copy), ue_byte_stream_get_size(to_copy))) {
        ei_stacktrace_push_msg("Failed to copy data from stream to copy to destination stream");
        return false;
    }

    return true;
}
