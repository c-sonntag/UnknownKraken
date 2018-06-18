/******************************************************************************************
 * Copyright (C) 2018 by Charly Lamothe													  *
 *																						  *
 * This file is part of LibUnknownEchoCryptoModule.										  *
 *																						  *
 *   LibUnknownEchoCryptoModule is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU General Public License as published by				  *
 *   the Free Software Foundation, either version 3 of the License, or					  *
 *   (at your option) any later version.												  *
 *																						  *
 *   LibUnknownEchoCryptoModule is distributed in the hope that it will be useful,        *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of						  *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  *
 *   GNU General Public License for more details.										  *
 *																						  *
 *   You should have received a copy of the GNU General Public License					  *
 *   along with LibUnknownEchoCryptoModule.  If not, see <http://www.gnu.org/licenses/>.  *
 ******************************************************************************************/

#include <uecm/byte/byte_reader.h>
#include <uecm/byte/byte_writer.h>
#include <ei/ei.h>
#include <uecm/alloc.h>
#include <uecm/string/string_utility.h>

#include <string.h>
#include <stddef.h>

bool uecm_byte_read_is_int(uecm_byte_stream *stream, int position, int n) {
    int read;

    if (!stream || !stream->bytes) {
        return false;
    }

    if (position + 3 >= stream->size) {
        ei_stacktrace_push_msg("Failed to get int because this would cause a buffer underflow");
        return false;
    }

    read = (stream->bytes[position] << 24) |
        (stream->bytes[position+1] << 16) |
        (stream->bytes[position+2] << 8) |
        stream->bytes[position+3];

    return read == n;
}

bool uecm_byte_read_next_int(uecm_byte_stream *stream, int *n) {
    if (!stream || !stream->bytes) {
        return false;
    }

    if (stream->position + 3 >= stream->size) {
        ei_stacktrace_push_msg("Failed to get int because this would cause a buffer underflow");
        return false;
    }

    *n = (stream->bytes[stream->position] << 24) |
        (stream->bytes[stream->position+1] << 16) |
        (stream->bytes[stream->position+2] << 8) |
        stream->bytes[stream->position+3];

    stream->position += 4;

    return true;
}

bool uecm_byte_read_next_bytes(uecm_byte_stream *stream, unsigned char **bytes, size_t len) {
    if (!stream || !stream->bytes) {
        return false;
    }

    if (stream->position + len >= stream->size) {
        ei_stacktrace_push_msg("Failed to get next bytes because this would cause a buffer underflow");
        return false;
    }

    uecm_safe_alloc(*bytes, unsigned char, len);
    memcpy(*bytes, stream->bytes + stream->position, len * sizeof(unsigned char));
    stream->position += len;

    return true;
}

bool uecm_byte_read_next_stream(uecm_byte_stream *stream, uecm_byte_stream *new_stream) {
    int read_int;
    unsigned char *read_bytes;

    if (!stream || !stream->bytes) {
        return false;
    }

    ei_check_parameter_or_return(new_stream);

    if (!uecm_byte_read_next_int(stream, &read_int)) {
        ei_stacktrace_push_msg("Failed to read new stream size");
        return false;
    }

    if (!uecm_byte_read_next_bytes(stream, &read_bytes, (size_t)read_int)) {
        ei_stacktrace_push_msg("Failed to read new stream content");
        return false;
    }

    if (!uecm_byte_writer_append_bytes(new_stream, read_bytes, (size_t)read_int)) {
        uecm_safe_free(read_bytes);
        ei_stacktrace_push_msg("Failed to write new stream content");
        return false;
    }

    uecm_safe_free(read_bytes);

    return true;
}

bool uecm_byte_read_next_string(uecm_byte_stream *stream, const char **string, size_t len) {
    unsigned char *bytes;

    ei_check_parameter_or_return(stream);
    ei_check_parameter_or_return(len > 0);

    if (!uecm_byte_read_next_bytes(stream, &bytes, len)) {
        ei_stacktrace_push_msg("Failed to read next %ld bytes", len);
        return false;
    }

    if ((*string = uecm_string_create_from_bytes(bytes, len)) == NULL) {
        ei_stacktrace_push_msg("Failed to convert %ld bytes to string", len);
        uecm_safe_free(bytes);
        return false;
    }

    uecm_safe_free(bytes);

    return true;
}

/*bool uecm_byte_read_remaining_bytes(uecm_byte_stream *stream, unsigned char **bytes, size_t *len) {
    size_t remaining_bytes_size;

    if (!stream || !stream->bytes) {
        return false;
    }

    ei_logger_debug("stream->size: %ld", stream->size);
    ei_logger_debug("stream->position: %ld", stream->position);
    ei_logger_debug("stream->size - stream->position: %ld", stream->size - stream->position);

    if ((remaining_bytes_size = stream->size - stream->position) <= 0) {
        ei_stacktrace_push_msg("There's no remaining bytes to read");
        return false;
    }

    if (!uecm_byte_read_next_bytes(stream, bytes, remaining_bytes_size)) {
        ei_stacktrace_push_msg("Failed to read remaining bytes");
        return false;
    }

    return true;
}*/
