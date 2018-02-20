#include <unknownecho/crypto/impl/errorHandling/zlib_error_handling.h>

#include <zlib.h>

void ue_zlib_error_handling_impl(int error_code) {
    switch (error_code) {
        case Z_ERRNO:
            if (ferror(stdin)) {
                ue_stacktrace_push_msg("Error reading stdin");
            } else if (ferror(stdout)) {
                ue_stacktrace_push_msg("Error reading stdout");
            }
        break;

        case Z_STREAM_ERROR:
            ue_stacktrace_push_msg("Invalid compression level");
        break;

        case Z_DATA_ERROR:
            ue_stacktrace_push_msg("Invalid or incomplete deflate data");
        break;

        case Z_MEM_ERROR:
            ue_stacktrace_push_msg("Out of memory");
        break;

        case Z_VERSION_ERROR:
            ue_stacktrace_push_msg("Zlib version mismatch");
        break;
    }
}
