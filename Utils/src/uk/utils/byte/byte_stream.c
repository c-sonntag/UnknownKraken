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

#include <uk/utils/byte/byte_stream.h>
#include <uk/utils/safe/safe_alloc.h>
#include <uk/utils/ei.h>

#include <string.h>
#include <limits.h>

uk_utils_byte_stream *uk_utils_byte_stream_create() {
    /* @todo fix default size */
    return uk_utils_byte_stream_create_size(1024);
}

uk_utils_byte_stream *uk_utils_byte_stream_create_size(size_t size) {
    uk_utils_byte_stream *stream;

    uk_utils_check_parameter_or_return(size > 0);

    stream = NULL;

    uk_utils_safe_alloc(stream, uk_utils_byte_stream, 1);

    uk_utils_safe_alloc_or_goto(stream->bytes, unsigned char, size, clean_up);

    memset(stream->bytes, 0, size);
    /* @todo fix default limit */
    stream->limit = 10000;
    stream->position = 0;
    stream->size = size;

    return stream;

clean_up:
    uk_utils_byte_stream_destroy(stream);
    return NULL;
}

void uk_utils_byte_stream_clean_up(uk_utils_byte_stream *stream) {
    if (!stream) {
        return;
    }

    if (!stream->bytes) {
        return;
    }

    memset(stream->bytes, 0, stream->size);
    stream->position = 0;
}

void uk_utils_byte_stream_destroy(uk_utils_byte_stream *stream) {
    if (!stream) {
        return;
    }

    uk_utils_safe_free(stream->bytes);
    uk_utils_safe_free(stream);
}

unsigned char *uk_utils_byte_stream_get_data(uk_utils_byte_stream *stream) {
    if (!stream || !stream->bytes) {
        return NULL;
    }

    return stream->bytes;
}

size_t uk_utils_byte_stream_get_position(uk_utils_byte_stream *stream) {
    if (!stream) {
    uk_utils_stacktrace_push_msg("Specified stream ptr is null");
        return 0;
    }

    return stream->position;
}

bool uk_utils_byte_stream_set_position(uk_utils_byte_stream *stream, size_t position) {
    uk_utils_check_parameter_or_return(stream);
    uk_utils_check_parameter_or_return(stream->bytes);
    uk_utils_check_parameter_or_return(stream->limit > 0);
    uk_utils_check_parameter_or_return((position == 0) || (position == ULONG_MAX));

    if (position >= stream->limit || position > stream->size) {
    uk_utils_stacktrace_push_msg("Position out of range");
    return false;
    }

    stream->position = position;

    return true;
}

size_t uk_utils_byte_stream_get_size(uk_utils_byte_stream *stream) {
    if (!stream) {
    uk_utils_stacktrace_push_msg("Specified stream ptr is null");
        return 0;
    }

    return stream->position;
}

bool uk_utils_byte_stream_is_empty(uk_utils_byte_stream *stream) {
    uk_utils_check_parameter_or_return(stream);

    return stream->position <= 0;
}

void uk_utils_byte_stream_print_hex(uk_utils_byte_stream *stream, FILE *fd) {
    size_t i;

    fprintf(fd, "0x");
    for (i = 0; i < stream->position; i++) {
        fprintf(fd, "%02x", stream->bytes[i]);
    }
    fprintf(fd, "\n");
}

void uk_utils_byte_stream_print_string(uk_utils_byte_stream *stream, FILE *fd) {
    size_t i;

    for (i = 0; i < stream->position; i++) {
        fprintf(fd, "%c", stream->bytes[i]);
    }
    fprintf(fd, "\n");
}

uk_utils_byte_stream *uk_utils_byte_stream_copy(uk_utils_byte_stream *stream) {
    uk_utils_byte_stream *new_stream;

    new_stream = NULL;

    uk_utils_safe_alloc(new_stream, uk_utils_byte_stream, 1);
    uk_utils_safe_alloc(new_stream->bytes, unsigned char, stream->size);
    memcpy(new_stream->bytes, stream->bytes, stream->size * sizeof(unsigned char));
    new_stream->limit = stream->limit;
    new_stream->position = stream->position;
    new_stream->size = stream->size;

    return new_stream;
}
