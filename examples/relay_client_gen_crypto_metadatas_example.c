#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/crypto/factory/crypto_metadata_factory.h>
#include <unknownecho/init.h>

#include <ei/ei.h>

#include <stdlib.h>

#define try_or_clean_up(exp, error_message, label) \
    if (!(exp)) { \
        ei_stacktrace_push_msg("%s", error_message); \
        goto label; \
    } \

int main() {
    ue_crypto_metadata *crypto_metadata;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ei_logger_info("UnknownEchoLib is correctly initialized.");

    try_or_clean_up(crypto_metadata = ue_crypto_metadata_write_if_not_exist("out/private", "out/public",
        "client1", "password"), "Failed to write crypto metadata for client1", end);
    ue_crypto_metadata_destroy(crypto_metadata);

    try_or_clean_up(crypto_metadata = ue_crypto_metadata_write_if_not_exist("out/private", "out/public",
        "client2", "password"), "Failed to write crypto metadata for client2", end);
    ue_crypto_metadata_destroy(crypto_metadata);

    try_or_clean_up(crypto_metadata = ue_crypto_metadata_write_if_not_exist("out/private", "out/public",
        "server1", "password"), "Failed to write crypto metadata for server1", end);
    ue_crypto_metadata_destroy(crypto_metadata);

    try_or_clean_up(crypto_metadata = ue_crypto_metadata_write_if_not_exist("out/private", "out/public",
        "server2", "password"), "Failed to write crypto metadata for server2", end);
    ue_crypto_metadata_destroy(crypto_metadata);

end:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    ue_uninit();
    return EXIT_SUCCESS;
}
