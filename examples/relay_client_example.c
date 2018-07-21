/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/init.h>
#include <unknownecho/protocol/api/relay/relay_client.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    READING_STATE,
    WRITING_STATE,
    CLOSING_STATE
} ue_data_transmission_state;

typedef struct {
    ue_relay_client *client;
    ueum_thread_mutex *mutex;
    ueum_thread_cond *cond;
    ue_data_transmission_state transmission_state;
    bool running;
    ueum_thread_id *read_consumer_thread, *write_consumer_thread;
} global_context;

uecm_crypto_metadata **remote_crypto_metadatas = NULL;
int remote_crypto_metadatas_number = 0;
global_context context;

static ue_relay_step *create_step_from_uid(uecm_crypto_metadata *our_crypto_metadata, char *target_uid, int target_port, int i) {

    ue_relay_step *step;
    uecm_crypto_metadata *target_crypto_metadata;

    if (!(target_crypto_metadata = uecm_crypto_metadata_create_empty())) {
        ei_stacktrace_push_msg("Failed to create empty crypto metadata object for target");
        return NULL;
    }

    if (!uecm_crypto_metadata_read_certificates(target_crypto_metadata, "out/public", target_uid)) {
        uecm_crypto_metadata_destroy(target_crypto_metadata);
        ei_stacktrace_push_msg("Failed to read certificates of target");
        return NULL;
    }

    if (!(step = ue_relay_step_create(ue_communication_metadata_create_socket_type(target_uid, "127.0.0.1", target_port),
        our_crypto_metadata, target_crypto_metadata))) {

        uecm_crypto_metadata_destroy(target_crypto_metadata);
        ei_stacktrace_push_msg("Failed to create step with uid '%s'", target_uid);
        return NULL;
    }

    remote_crypto_metadatas[i] = target_crypto_metadata;

    return step;
}

static ue_relay_route *create_route_from_args(uecm_crypto_metadata *our_crypto_metadata, int argc, char **argv) {
    ue_relay_route *route;
    ue_relay_step **steps;
    int step_number;
    int i, j;

    route = NULL;
    steps = NULL;
    step_number = (argc - 3)/2;
    remote_crypto_metadatas = NULL;
    
    ueum_safe_alloc(steps, ue_relay_step *, step_number);
    ueum_safe_alloc(remote_crypto_metadatas, uecm_crypto_metadata *, step_number);
    remote_crypto_metadatas_number = step_number;

    for (i = 3, j = 0; i < argc; i+=2, j++) {
        if (!(steps[j] = create_step_from_uid(our_crypto_metadata, argv[i], atoi(argv[i+1]), j))) {
            ei_stacktrace_push_msg("Failed to create step at iteration %d with uid '%s'", j, argv[i]);
            goto clean_up_fail;
        }
    }

    if (!(route = ue_relay_route_create(steps, step_number))) {
        ei_stacktrace_push_msg("Failed to create new relay route");
        goto clean_up_fail;
    }

    return route;

clean_up_fail:
    if (steps) {
        for (i = 0; i < step_number; i++) {
            uecm_crypto_metadata_destroy_all(ue_relay_step_get_target_crypto_metadata(steps[i]));
            ue_relay_step_destroy(steps[i]);
        }
        ueum_safe_free(steps);
    }
    return NULL;
}

static bool send_message(ueum_byte_stream *message_to_send) {
    bool result;

    ei_check_parameter_or_return(message_to_send);
    ei_check_parameter_or_return(!ueum_byte_stream_is_empty(message_to_send));

    result = false;

    ueum_thread_mutex_lock(context.mutex);
    context.transmission_state = WRITING_STATE;
    result = ue_relay_client_send_message(context.client, message_to_send);
    context.transmission_state = READING_STATE;
    ueum_thread_cond_signal(context.cond);
    ueum_thread_mutex_unlock(context.mutex);

    return result;
}

static bool receive_message(ueum_byte_stream *received_message) {
    ueum_thread_mutex_lock(context.mutex);
    while (context.transmission_state == WRITING_STATE) {
        ueum_thread_cond_wait(context.cond, context.mutex);
    }
    ueum_thread_mutex_unlock(context.mutex);

    return ue_relay_client_receive_message(context.client, received_message);
}

/*static bool send_cipher_message(ue_channel_client *channel_client, void *connection, ueum_byte_stream *message_to_send) {
    bool result;
    unsigned char *cipher_data;
    size_t cipher_data_size;
    uecm_x509_certificate *server_certificate;
    uecm_public_key *server_public_key;
    result = false;
    cipher_data = NULL;
    server_public_key = NULL;
    if (!(server_certificate = uecm_pkcs12_keystore_find_certificate_by_friendly_name(context.cipher_keystore, (const unsigned char *)"CIPHER_SERVER", strlen("CIPHER_SERVER")))) {
        ei_stacktrace_push_msg("Failed to get cipher client certificate");
        goto clean_up;
    }
    if (!(server_public_key = uecm_rsa_public_key_from_x509_certificate(server_certificate))) {
        ei_stacktrace_push_msg("Failed to get server public key from server certificate");
        goto clean_up;
    }
    if (!uecm_cipher_plain_data(ueum_byte_stream_get_data(message_to_send), ueum_byte_stream_get_size(message_to_send),
        server_public_key, context.signer_keystore->private_key, &cipher_data, &cipher_data_size, context.cipher_name,
        context.digest_name)) {
        ei_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }
    ueum_byte_stream_clean_up(context.message_to_send);
    if (!ueum_byte_writer_append_bytes(context.message_to_send, cipher_data, cipher_data_size)) {
        ei_stacktrace_push_msg("Failed to write cipher data to message to send");
        goto clean_up;
    }
    if (!send_message(channel_client, connection, context.message_to_send)) {
        ei_stacktrace_push_msg("Failed to send cipher message");
        goto clean_up;
    }
    result = true;
clean_up:
    ueum_safe_free(cipher_data);
    uecm_public_key_destroy(server_public_key);
    return result;
}
static size_t receive_cipher_message(ue_channel_client *channel_client, void *connection) {
    unsigned char *plain_data;
    size_t received, plain_data_size;
    uecm_x509_certificate *server_certificate;
    uecm_public_key *server_public_key;
    plain_data = NULL;
    server_public_key = NULL;
    received = receive_message(channel_client, connection);
    if (received <= 0 || received == ULLONG_MAX) {
        ei_logger_warn("Connection with server is interrupted.");
        goto clean_up;
    }
    if (!(server_certificate = uecm_pkcs12_keystore_find_certificate_by_friendly_name(context.signer_keystore, (const unsigned char *)"SIGNER_SERVER", strlen("SIGNER_SERVER")))) {
        ei_stacktrace_push_msg("Failed to find server signer certificate");
        received = -1;
        goto clean_up;
    }
    if (!(server_public_key = uecm_rsa_public_key_from_x509_certificate(server_certificate))) {
        ei_stacktrace_push_msg("Failed to get server public key from server certificate");
        received = -1;
        goto clean_up;
    }
    if (!uecm_decipher_cipher_data(ueum_byte_stream_get_data(context.received_message),
        ueum_byte_stream_get_size(context.received_message), context.cipher_keystore->private_key,
        server_public_key, &plain_data, &plain_data_size, context.cipher_name,
        context.digest_name)) {
        received = -1;
        ei_stacktrace_push_msg("Failed decipher message data");
        goto clean_up;
    }
    ueum_byte_stream_clean_up(context.received_message);
    if (!ueum_byte_writer_append_bytes(context.received_message, plain_data, plain_data_size)) {
        received = -1;
        ei_stacktrace_push_msg("Failed to write plain data to received message");
        goto clean_up;
    }
clean_up:
    uecm_public_key_destroy(server_public_key);
    ueum_safe_free(plain_data);
    return received;
}*/

static void read_consumer(void *parameter) {
    ueum_byte_stream *received_message;

    received_message = ueum_byte_stream_create();

    while (context.running) {
        if (!receive_message(received_message)) {
            ei_logger_stacktrace("Failed to receive message");
            ei_stacktrace_clean_up();
        }
        ueum_byte_stream_print_string(received_message, stdout);
        if (memcmp(ueum_byte_stream_get_data(received_message), "-s", strlen("-s")) == 0) {
            context.running = false;
            break;
        }
    }

    ueum_byte_stream_destroy(received_message);
}

static void write_consumer(void *parameter) {
    char *input;
    ueum_byte_stream *message;

    if (!(message = ueum_byte_stream_create())) {
        ei_stacktrace_push_msg("Failed to create empty byte stream");
        return;
    }

    while (context.running) {
        input = ueum_input_string(">");

        if (!input) {
            continue;
        }

        if (strcmp(input, "-q") == 0) {
            context.running = false;
            break;
        }

        ueum_byte_stream_clean_up(message);
        ueum_byte_writer_append_string(message, input);

        if (!send_message(message)) {
            ei_logger_stacktrace("Failed to send message to server");
        } else {
            ei_logger_info("Message sent.");
        }

        ueum_safe_free(input);
    }

    ueum_safe_free(input);
    ueum_byte_stream_destroy(message);
}

int main(int argc, char **argv) {
    ue_relay_route *route;
    ue_communication_metadata *our_communication_metadata;
    uecm_crypto_metadata *our_crypto_metadata;
    int i;

    route = NULL;
    our_crypto_metadata = NULL;
    remote_crypto_metadatas = NULL;
    remote_crypto_metadatas_number = 0;
    our_communication_metadata = NULL;

    if (argc < 4) {
        fprintf(stdout, "Usage: %s <client_uid> <client_password> <server_uid> <server_port> [server_uid server_port ...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ei_logger_info("LibUnknownEcho is correctly initialized.");

    context.mutex = ueum_thread_mutex_create();
    context.cond = ueum_thread_cond_create();
    context.client = NULL;
    context.transmission_state = WRITING_STATE;
    context.running = true;

    if (!(our_crypto_metadata = uecm_crypto_metadata_write_if_not_exist("out/private", "out/public", argv[1], argv[2]))) {
        ei_stacktrace_push_msg("Failed to get crypto metadata");
        goto clean_up;
    }

    if (!(route = create_route_from_args(our_crypto_metadata, argc, argv))) {
        ei_stacktrace_push_msg("Failed to create route from args");
        goto clean_up;
    }

    if (!ue_relay_route_is_valid(route)) {
        ei_stacktrace_push_msg("New route is invalid");
        goto clean_up;
    }

    our_communication_metadata = ue_communication_metadata_create_socket_type(argv[1], "127.0.0.1", 0);

    if (!(context.client = ue_relay_client_create_from_route(our_communication_metadata, route))) {
        ei_stacktrace_push_msg("Failed to create new relay client");
        goto clean_up;
    }

    if (!ue_relay_client_is_valid(context.client)) {
        ei_stacktrace_push_msg("New relay client is invalid");
        goto clean_up;
    }
    ei_logger_info("New relay client is valid");

    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
        context.read_consumer_thread = ueum_thread_create(read_consumer, NULL);
        context.write_consumer_thread = ueum_thread_create(write_consumer, NULL);
    _Pragma("GCC diagnostic pop")

    ueum_thread_join(context.read_consumer_thread, NULL);
    ueum_thread_join(context.write_consumer_thread, NULL);

clean_up:
    ue_relay_client_destroy(context.client);
    ueum_thread_mutex_destroy(context.mutex);
    ueum_thread_cond_destroy(context.cond);
    uecm_crypto_metadata_destroy_all(our_crypto_metadata);
    ue_relay_route_destroy(route);
    if (remote_crypto_metadatas) {
        for (i = 0; i < remote_crypto_metadatas_number; i++) {
            uecm_crypto_metadata_destroy_all(remote_crypto_metadatas[i]);
        }
        ueum_safe_free(remote_crypto_metadatas);
    }
    ue_communication_metadata_destroy(our_communication_metadata);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
