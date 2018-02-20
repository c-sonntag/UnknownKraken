#include <unknownecho/init.h>
#include <unknownecho/model/message/plain_message.h>
#include <unknownecho/model/message/cipher_message.h>
#include <unknownecho/model/message/decipher_message.h>
#include <unknownecho/model/manager/pgp_keystore_manager.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/byte/hex_utility.h>
#include <unknownecho/system/alloc.h>

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int exit_code;
    ue_plain_message *input_pmsg, *output_pmsg;
    ue_cipher_message *cmsg, *received_cmsg;
    unsigned char *ue_cipher_message;
    size_t ue_cipher_message_size;
    ue_pgp_keystore_manager *cipher_keystore_manager, *decipher_keystore_manager;
    char *plaintext, *hex_ciphered_message;

    exit_code = EXIT_FAILURE;
    input_pmsg = NULL;
    output_pmsg = NULL;
    cmsg = NULL;
    received_cmsg = NULL;
    ue_cipher_message = NULL;
    cipher_keystore_manager = NULL;
    decipher_keystore_manager = NULL;
    plaintext = NULL;
    hex_ciphered_message = NULL;

    if (argc == 1) {
        fprintf(stderr, "[FATAL] An argument is required\n");
        exit(EXIT_FAILURE);
    }

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize UnknownEchoLib\n");
        exit(EXIT_FAILURE);
    }
    ue_logger_info("UnknownEchoLib is correctly initialized");

    ue_logger_info("Loading cipher pgp keystore manager with client certificates...");
    if (!(cipher_keystore_manager = ue_pgp_keystore_manager_init("res/pem/c1_pgp_pub.pem", "res/pem/c1_pgp_priv.pem", "res/pem/server_pgp_pub.pem", NULL))) {
        ue_stacktrace_push_msg("Failed to init sender keystore manager")
        goto clean_up;
    }
    ue_logger_info("Cipher pgp keystore manager successfully loaded");

    ue_logger_info("Loading decipher pgp keystore manager with server certificates...");
    if (!(decipher_keystore_manager = ue_pgp_keystore_manager_init("res/pem/c2_pgp_pub.pem", "res/pem/c2_pgp_priv.pem", "res/pem/server_pgp_pub.pem", NULL))) {
        ue_stacktrace_push_msg("Failed to init receiver keystore manager")
        goto clean_up;
    }
    ue_logger_info("Decipher pgp keystore manager successfully loaded");

    ue_logger_info("Creating plain message from parameter...");
    if (!(input_pmsg = ue_plain_message_create(cipher_keystore_manager, "dest", "src", argv[1], "MSG"))) {
        ue_stacktrace_push_msg("Failed to create plain message")
        goto clean_up;
    }

    if (!(plaintext = ue_plain_message_to_string(input_pmsg))) {
        ue_stacktrace_push_msg("Failed to convert output plain message to string")
        goto clean_up;
    }
    ue_logger_info("Plaintext input message is : %s", plaintext);;
    ue_safe_free(plaintext)
    plaintext = NULL;

    ue_logger_info("Building ciphered message as client...");
    if (!(cmsg = ue_message_build_encrypted_as_client(cipher_keystore_manager, input_pmsg))) {
        ue_stacktrace_push_msg("Failed to encrypt plain msg")
        goto clean_up;
    }
    ue_logger_info("Message ciphered");

    ue_logger_info("Converting ciphered message to bytes...");
    if (!(ue_cipher_message = ue_cipher_message_to_data(cmsg, &ue_cipher_message_size))) {
        ue_stacktrace_push_msg("Failed to convert cipher message to bytes")
        goto clean_up;
    }

    hex_ciphered_message = ue_bytes_to_hex(ue_cipher_message, ue_cipher_message_size);
    ue_logger_debug("Ciphered message : %s", hex_ciphered_message);
    ue_safe_free(hex_ciphered_message)

    ue_logger_info("Let say the client 2 received the ciphered data");
    if (!(received_cmsg = ue_data_to_cipher_message(ue_cipher_message, ue_cipher_message_size))) {
        ue_stacktrace_push_msg("Failed to convert received message data to cipher message")
        goto clean_up;
    }

    ue_logger_info("Deciphering message as client...");
    if (!(output_pmsg = ue_message_build_decrypted_as_client(decipher_keystore_manager, received_cmsg))) {
        ue_stacktrace_push_msg("Failed to decrypt message")
        goto clean_up;
    }
    ue_logger_info("Message deciphered");

    ue_logger_info("Recovering plain message...");
    if (!(plaintext = ue_plain_message_to_string(output_pmsg))) {
        ue_stacktrace_push_msg("Failed to convert output plain message to string")
        goto clean_up;
    }
    ue_logger_debug("Recovered message is : '%s'", plaintext);

    if (ue_plain_message_equals(input_pmsg, output_pmsg)) {
        ue_logger_info("Both plain message are equals");
    } else {
        ue_stacktrace_push_msg("Comparaison of both message failed")
        ue_logger_error("Both plain message aren't equals");
        goto clean_up;
    }

    exit_code = EXIT_SUCCESS;

clean_up:
    ue_plain_message_destroy(input_pmsg);
    ue_plain_message_destroy(output_pmsg);
    ue_cipher_message_destroy(cmsg);
    ue_cipher_message_destroy(received_cmsg);
    ue_safe_free(ue_cipher_message)
    ue_safe_free(plaintext)
    ue_pgp_keystore_manager_uninit(cipher_keystore_manager);
    ue_pgp_keystore_manager_uninit(decipher_keystore_manager);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return exit_code;
}
