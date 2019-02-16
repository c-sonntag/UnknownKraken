/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoUtilsModule.                             *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <ueum/byte/byte_writer.h>
#include <ueum/byte/byte_stream.h>
#include <ueum/safe/safe_alloc.h>
#include <ei/ei.h>

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

bool ueum_byte_writer_append_bytes(ueum_byte_stream *stream, unsigned char *bytes, size_t bytes_len) {
    ei_check_parameter_or_return(stream);
    ei_check_parameter_or_return(bytes);
    ei_check_parameter_or_return(bytes_len > 0 && bytes_len != 18446744073709551615UL);

    if ((bytes_len + stream->position) > stream->size) {
        ueum_safe_realloc(stream->bytes, unsigned char, stream->size, bytes_len + stream->size);
        stream->size += bytes_len;
    }

    memcpy(stream->bytes + stream->position, bytes, bytes_len);

    stream->position += bytes_len;

    return true;
}

bool ueum_byte_writer_append_string(ueum_byte_stream *stream, const char *string) {
    size_t string_len;

    ei_check_parameter_or_return(stream);
    ei_check_parameter_or_return(string);

    string_len = strlen(string);

    ei_check_parameter_or_return(string_len > 0 && string_len != 18446744073709551615UL);

    if ((string_len + stream->position) > stream->size) {
        ueum_safe_realloc(stream->bytes, unsigned char, stream->size, string_len + stream->size);
        stream->size += string_len;
    }

    memcpy(stream->bytes + stream->position, string, string_len);

    stream->position += string_len;

    return true;
}

bool ueum_byte_writer_append_byte(ueum_byte_stream *stream, unsigned char byte) {
    ei_check_parameter_or_return(stream);

    if ((1 + stream->position) > stream->size) {
        ueum_safe_realloc(stream->bytes, unsigned char, stream->size, 1 + stream->size);
        stream->size += 1;
    }

    stream->bytes[stream->position++] = byte;

    return true;
}

bool ueum_byte_writer_append_int(ueum_byte_stream *stream, int n) {
    ei_check_parameter_or_return(stream);

    if ((4 + stream->position) > stream->size) {
        ueum_safe_realloc(stream->bytes, unsigned char, stream->size, 4 + stream->size);
        stream->size += 4;
    }

    stream->bytes[stream->position++] = (n >> 24) & 0xFF;
    stream->bytes[stream->position++] = (n >> 16) & 0xFF;
    stream->bytes[stream->position++] = (n >> 8) & 0xFF;
    stream->bytes[stream->position++] = n & 0xFF;

    return true;
}

bool ueum_byte_writer_append_long(ueum_byte_stream *stream, long int n) {
   ei_check_parameter_or_return(stream);

    if ((8 + stream->position) > stream->size) {
        ueum_safe_realloc(stream->bytes, unsigned char, stream->size, 8 + stream->size);
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

bool ueum_byte_writer_append_stream(ueum_byte_stream *stream, ueum_byte_stream *to_copy) {
    ei_check_parameter_or_return(stream);
    ei_check_parameter_or_return(to_copy);

    if (ueum_byte_stream_is_empty(to_copy)) {
        ei_stacktrace_push_msg("Specified stream to copy is empty");
        return false;
    }

    /* Set the virtual cursor of the byte stream to the begining for safety */

    if (!ueum_byte_writer_append_int(stream, (int)ueum_byte_stream_get_size(to_copy))) {
        ei_stacktrace_push_msg("Failed to write data size to destination stream");
        return false;
    }

    if (!ueum_byte_writer_append_bytes(stream, ueum_byte_stream_get_data(to_copy), ueum_byte_stream_get_size(to_copy))) {
        ei_stacktrace_push_msg("Failed to copy data from stream to copy to destination stream");
        return false;
    }

    return true;
}
