#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/system/alloc.h>

#include <string.h>

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

    /*if (stream->position + len >= stream->size) {
        ue_stacktrace_push_msg("Failed to get next bytes because this would cause a buffer underflow");
        return false;
    }*/

    ue_safe_alloc(*bytes, unsigned char, len);
    memcpy(*bytes, stream->bytes + stream->position, len * sizeof(unsigned char));
    stream->position += len;

    return true;
}
