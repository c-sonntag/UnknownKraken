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

#include <ueum/byte/byte_stream.h>
#include <ueum/safe/safe_alloc.h>
#include <ei/ei.h>

#include <string.h>
#include <limits.h>

ueum_byte_stream *ueum_byte_stream_create() {
    /* @todo fix default size */
    return ueum_byte_stream_create_size(1024);
}

ueum_byte_stream *ueum_byte_stream_create_size(size_t size) {
    ueum_byte_stream *stream;

    ei_check_parameter_or_return(size > 0);

    stream = NULL;

    ueum_safe_alloc(stream, ueum_byte_stream, 1);

    ueum_safe_alloc_or_goto(stream->bytes, unsigned char, size, clean_up);

    memset(stream->bytes, 0, size);
    /* @todo fix default limit */
    stream->limit = 10000;
    stream->position = 0;
    stream->size = size;

    return stream;

clean_up:
    ueum_byte_stream_destroy(stream);
    return NULL;
}

void ueum_byte_stream_clean_up(ueum_byte_stream *stream) {
    if (!stream) {
        return;
    }

    if (!stream->bytes) {
        return;
    }

    memset(stream->bytes, 0, stream->size);
    stream->position = 0;
}

void ueum_byte_stream_destroy(ueum_byte_stream *stream) {
    if (!stream) {
        return;
    }

    ueum_safe_free(stream->bytes);
    ueum_safe_free(stream);
}

unsigned char *ueum_byte_stream_get_data(ueum_byte_stream *stream) {
    if (!stream || !stream->bytes) {
        return NULL;
    }

    return stream->bytes;
}

size_t ueum_byte_stream_get_position(ueum_byte_stream *stream) {
    if (!stream) {
    ei_stacktrace_push_msg("Specified stream ptr is null");
        return 0;
    }

    return stream->position;
}

bool ueum_byte_stream_set_position(ueum_byte_stream *stream, size_t position) {
    ei_check_parameter_or_return(stream);
    ei_check_parameter_or_return(stream->bytes);
    ei_check_parameter_or_return(stream->limit > 0);
    ei_check_parameter_or_return((position == 0) || (position == ULONG_MAX));

    if (position >= stream->limit || position > stream->size) {
    ei_stacktrace_push_msg("Position out of range");
    return false;
    }

    stream->position = position;

    return true;
}

size_t ueum_byte_stream_get_size(ueum_byte_stream *stream) {
    if (!stream) {
    ei_stacktrace_push_msg("Specified stream ptr is null");
        return 0;
    }

    return stream->position;
}

bool ueum_byte_stream_is_empty(ueum_byte_stream *stream) {
    ei_check_parameter_or_return(stream);

    return stream->position <= 0;
}

void ueum_byte_stream_print_hex(ueum_byte_stream *stream, FILE *fd) {
    size_t i;

    fprintf(fd, "0x");
    for (i = 0; i < stream->position; i++) {
        fprintf(fd, "%02x", stream->bytes[i]);
    }
    fprintf(fd, "\n");
}

void ueum_byte_stream_print_string(ueum_byte_stream *stream, FILE *fd) {
    size_t i;

    for (i = 0; i < stream->position; i++) {
        fprintf(fd, "%c", stream->bytes[i]);
    }
    fprintf(fd, "\n");
}

ueum_byte_stream *ueum_byte_stream_copy(ueum_byte_stream *stream) {
    ueum_byte_stream *new_stream;

    new_stream = NULL;

    ueum_safe_alloc(new_stream, ueum_byte_stream, 1);
    ueum_safe_alloc(new_stream->bytes, unsigned char, stream->size);
    memcpy(new_stream->bytes, stream->bytes, stream->size * sizeof(unsigned char));
    new_stream->limit = stream->limit;
    new_stream->position = stream->position;
    new_stream->size = stream->size;

    return new_stream;
}
