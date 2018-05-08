#include <unknownecho/init.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/crypto/factory/crypto_metadata_factory.h>

int main() {
    ue_crypto_metadata *our_crypto_metadata, *read_crypto_metadata;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ue_logger_info("UnknownEchoLib is correctly initialized");

    our_crypto_metadata = NULL;
    read_crypto_metadata = ue_crypto_metadata_create_empty();

    ue_logger_info("Generating crypto metadata for point A...");
    if (!(our_crypto_metadata = ue_crypto_metadata_create_default())) {
        ue_stacktrace_push_msg("Failed to generate default crypto metadata for point A");
        goto clean_up;
    }

    ue_logger_info("Writing our crypto metadata...");
    if (!ue_crypto_metadata_write(our_crypto_metadata, "out", "uid", "password")) {
        ue_stacktrace_push_msg("Failed to write our crypto metadata");
        goto clean_up;
    }
    ue_logger_info("Successfully wrote our crypto metadata");

    if (!ue_crypto_metadata_read(read_crypto_metadata, "out", "uid", "password")) {
        ue_stacktrace_push_msg("Failed to read our crypto metadata");
        goto clean_up;
    }
    ue_logger_info("Successfully read our crypto metadata");

clean_up:
    ue_crypto_metadata_destroy_all(our_crypto_metadata);
    ue_crypto_metadata_destroy_all(read_crypto_metadata);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
