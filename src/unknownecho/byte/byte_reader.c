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

#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/alloc.h>

#include <string.h>

bool ue_byte_read_is_int(ue_byte_stream *stream, int position, int n) {
    int read;

    if (!stream || !stream->bytes) {
        return false;
    }

    if (position + 3 >= stream->size) {
        ue_stacktrace_push_msg("Failed to get int because this would cause a buffer underflow");
        return false;
    }

    read = (stream->bytes[position] << 24) |
        (stream->bytes[position+1] << 16) |
        (stream->bytes[position+2] << 8) |
        stream->bytes[position+3];

    return read == n;
}

bool ue_byte_read_next_int(ue_byte_stream *stream, int *n) {
    if (!stream || !stream->bytes) {
        return false;
    }

    if (stream->position + 3 >= stream->size) {
        ue_stacktrace_push_msg("Failed to get int because this would cause a buffer underflow");
        return false;
    }

    *n = (stream->bytes[stream->position] << 24) |
        (stream->bytes[stream->position+1] << 16) |
        (stream->bytes[stream->position+2] << 8) |
        stream->bytes[stream->position+3];

    stream->position += 4;

    return true;
}

bool ue_byte_read_next_bytes(ue_byte_stream *stream, unsigned char **bytes, size_t len) {
    if (!stream || !stream->bytes) {
        return false;
    }

    if (stream->position + len >= stream->size) {
        ue_stacktrace_push_msg("Failed to get next bytes because this would cause a buffer underflow");
        return false;
    }

    ue_safe_alloc(*bytes, unsigned char, len);
    memcpy(*bytes, stream->bytes + stream->position, len * sizeof(unsigned char));
    stream->position += len;

    return true;
}
