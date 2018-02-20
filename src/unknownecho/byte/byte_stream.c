#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>

#include <string.h>

ue_byte_stream *ue_byte_stream_create() {
	return ue_byte_stream_create_limit(700);
}

ue_byte_stream *ue_byte_stream_create_limit(size_t limit) {
	ue_byte_stream *stream;

    ue_check_parameter_or_return(limit > 0);

    ue_safe_alloc(stream, ue_byte_stream, 1);

    ue_safe_alloc_or_goto(stream->bytes, unsigned char, limit + 1, clean_up);

    memset(stream->bytes, 0, limit);
    stream->limit = limit;
    stream->position = 0;
    stream->size = 0;

    return stream;

clean_up:
    ue_byte_stream_destroy(stream);
    return NULL;
}

void ue_byte_stream_clean_up(ue_byte_stream *stream) {
	if (!stream) {
        return;
    }

    if (!stream->bytes) {
        return;
    }

    memset(stream->bytes, 0, stream->limit);
    stream->position = 0;
    stream->size = 0;
}

void ue_byte_stream_destroy(ue_byte_stream *stream) {
	if (!stream) {
        return;
    }

    ue_safe_free(stream->bytes);
    ue_safe_free(stream);
}

unsigned char *ue_byte_stream_get_data(ue_byte_stream *stream) {
	if (!stream || !stream->bytes) {
        return NULL;
    }

    return stream->bytes;
}

size_t ue_byte_stream_get_position(ue_byte_stream *stream) {
	if (!stream) {
        return -1;
    }

    return stream->position;
}

bool ue_byte_stream_set_position(ue_byte_stream *stream, size_t position) {
    ue_check_parameter_or_return(stream);
    ue_check_parameter_or_return(stream->bytes);
    ue_check_parameter_or_return(stream->limit > 0);
    ue_check_parameter_or_return(position >= 0 && position < 18446744073709551615UL);

	if (position >= stream->limit || position > stream->size) {
		ue_stacktrace_push_msg("Position out of range");
		return false;
	}

    stream->position = position;

    return true;
}

size_t ue_byte_stream_get_size(ue_byte_stream *stream) {
    if (!stream) {
        return -1;
    }

    return stream->size;
}

void ue_byte_stream_print(ue_byte_stream *stream) {
    size_t i;

    printf("0x");
    for (i = 0; i < stream->size; i++) {
        printf("%02x", stream->bytes[i]);
    }
    printf("\n");
}
