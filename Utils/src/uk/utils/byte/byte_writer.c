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

#include <uk/utils/byte/byte_writer.h>
#include <uk/utils/byte/byte_stream.h>
#include <uk/utils/safe/safe_alloc.h>
#include <uk/utils/ei.h>

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

bool uk_utils_byte_writer_append_bytes(uk_utils_byte_stream *stream, unsigned char *bytes, size_t bytes_len) {
    uk_utils_check_parameter_or_return(stream);
    uk_utils_check_parameter_or_return(bytes);
    uk_utils_check_parameter_or_return(bytes_len > 0 && bytes_len != 18446744073709551615UL);

    if ((bytes_len + stream->position) > stream->size) {
        uk_utils_safe_realloc(stream->bytes, unsigned char, stream->size, bytes_len + stream->size);
        stream->size += bytes_len;
    }

    memcpy(stream->bytes + stream->position, bytes, bytes_len);

    stream->position += bytes_len;

    return true;
}

bool uk_utils_byte_writer_append_string(uk_utils_byte_stream *stream, const char *string) {
    size_t string_len;

    uk_utils_check_parameter_or_return(stream);
    uk_utils_check_parameter_or_return(string);

    string_len = strlen(string);

    uk_utils_check_parameter_or_return(string_len > 0 && string_len != 18446744073709551615UL);

    if ((string_len + stream->position) > stream->size) {
        uk_utils_safe_realloc(stream->bytes, unsigned char, stream->size, string_len + stream->size);
        stream->size += string_len;
    }

    memcpy(stream->bytes + stream->position, string, string_len);

    stream->position += string_len;

    return true;
}

bool uk_utils_byte_writer_append_byte(uk_utils_byte_stream *stream, unsigned char byte) {
    uk_utils_check_parameter_or_return(stream);

    if ((1 + stream->position) > stream->size) {
        uk_utils_safe_realloc(stream->bytes, unsigned char, stream->size, 1 + stream->size);
        stream->size += 1;
    }

    stream->bytes[stream->position++] = byte;

    return true;
}

bool uk_utils_byte_writer_append_int(uk_utils_byte_stream *stream, int n) {
    uk_utils_check_parameter_or_return(stream);

    if ((4 + stream->position) > stream->size) {
        uk_utils_safe_realloc(stream->bytes, unsigned char, stream->size, 4 + stream->size);
        stream->size += 4;
    }

    stream->bytes[stream->position++] = (n >> 24) & 0xFF;
    stream->bytes[stream->position++] = (n >> 16) & 0xFF;
    stream->bytes[stream->position++] = (n >> 8) & 0xFF;
    stream->bytes[stream->position++] = n & 0xFF;

    return true;
}

bool uk_utils_byte_writer_append_long(uk_utils_byte_stream *stream, long int n) {
   uk_utils_check_parameter_or_return(stream);

    if ((8 + stream->position) > stream->size) {
        uk_utils_safe_realloc(stream->bytes, unsigned char, stream->size, 8 + stream->size);
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

bool uk_utils_byte_writer_append_stream(uk_utils_byte_stream *stream, uk_utils_byte_stream *to_copy) {
    uk_utils_check_parameter_or_return(stream);
    uk_utils_check_parameter_or_return(to_copy);

    if (uk_utils_byte_stream_is_empty(to_copy)) {
        uk_utils_stacktrace_push_msg("Specified stream to copy is empty");
        return false;
    }

    /* Set the virtual cursor of the byte stream to the begining for safety */

    if (!uk_utils_byte_writer_append_int(stream, (int)uk_utils_byte_stream_get_size(to_copy))) {
        uk_utils_stacktrace_push_msg("Failed to write data size to destination stream");
        return false;
    }

    if (!uk_utils_byte_writer_append_bytes(stream, uk_utils_byte_stream_get_data(to_copy), uk_utils_byte_stream_get_size(to_copy))) {
        uk_utils_stacktrace_push_msg("Failed to copy data from stream to copy to destination stream");
        return false;
    }

    return true;
}
