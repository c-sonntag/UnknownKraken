#include <unknownecho/init.h>
#include <unknownecho/crypto/api/signature/signer.h>
#include <unknownecho/crypto/factory/rsa_signer_factory.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/system/alloc.h>

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

int main(int argc, char **argv) {
    int exit_code;
    ue_signer *s;
    unsigned char *signature, *message;
    size_t signature_length, message_length;
    ue_asym_key *akey;

    exit_code = EXIT_FAILURE;
    s = NULL;
    signature = NULL;
    akey = NULL;

    if (argc == 1) {
        fprintf(stderr, "[FATAL] An argument is required\n");
        exit(EXIT_FAILURE);
    }

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize UnknownEchoLib\n");
        exit(EXIT_FAILURE);
    }
    ue_logger_info("UnknownEchoLib is correctly initialized");

    ue_logger_info("Converting parameter '%s' to bytes...", argv[1]);
    if (!(message = ue_bytes_create_from_string(argv[1]))) {
        ue_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    ue_logger_info("Succefully converted parameter to bytes");

    message_length = strlen(argv[1]);

    akey = ue_rsa_asym_key_create(2048);

    ue_logger_info("Creating rsa ue_signer with random asym key of 2048 bits...");
    if (!(s = ue_rsa_signer_create_from_pair(akey))) {
        ue_stacktrace_push_msg("Failed to create rsa ue_signer with random asym key")
        goto clean_up;
    }
    ue_logger_info("Rsa ue_signer has been successfully created");

    ue_logger_info("Signing message with rsa ue_signer instance...");
    if (!(signature = ue_signer_sign_buffer(s, message, message_length, &signature_length))) {
        ue_stacktrace_push_msg("Failed to sign message")
        goto clean_up;
    }
    ue_logger_info("Message successfully signed");

    ue_logger_info("Verifying signature...");
    if ((ue_signer_verify_buffer(s, message, message_length, signature, signature_length))) {
        ue_logger_info("Signature matched with previous message");
    } else {
        ue_logger_error("Signature doesn't matched with previous message");
        ue_stacktrace_push_msg("Signature and buffer doesn't matched")
        goto clean_up;
    }

    exit_code = EXIT_SUCCESS;

clean_up:
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_safe_free(message);
    ue_safe_free(signature);
    ue_signer_destroy(s);
    ue_asym_key_destroy_all(akey);
    ue_uninit();
    return exit_code;
}
