#include <unknownecho/init.h>
#include <unknownecho/alloc.h>
#include <unknownecho/protocol/api/relay/relay_client.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <ei/ei.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/crypto/factory/crypto_metadata_factory.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/bool.h>
#include <unknownecho/console/input.h>

#include <uv.h>

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
    uv_mutex_t mutex;
    uv_cond_t cond;
    ue_data_transmission_state transmission_state;
    bool running;
    uv_thread_t read_consumer_thread, write_consumer_thread;
} global_context;

ue_crypto_metadata **remote_crypto_metadatas = NULL;
int remote_crypto_metadatas_number = 0;
global_context context;

static ue_relay_step *create_step_from_uid(ue_crypto_metadata *our_crypto_metadata, char *target_uid, int target_port, int i) {

    ue_relay_step *step;
    ue_crypto_metadata *target_crypto_metadata;

    if (!(target_crypto_metadata = ue_crypto_metadata_create_empty())) {
        ei_stacktrace_push_msg("Failed to create empty crypto metadata object for target");
        return NULL;
    }

    if (!ue_crypto_metadata_read_certificates(target_crypto_metadata, "out/public", target_uid)) {
        ue_crypto_metadata_destroy(target_crypto_metadata);
        ei_stacktrace_push_msg("Failed to read certificates of target");
        return NULL;
    }

    if (!(step = ue_relay_step_create(ue_communication_metadata_create_socket_type("127.0.0.1", target_port),
        our_crypto_metadata, target_crypto_metadata))) {

        ue_crypto_metadata_destroy(target_crypto_metadata);
        ei_stacktrace_push_msg("Failed to create step with uid '%s'", target_uid);
        return NULL;
    }

    remote_crypto_metadatas[i] = target_crypto_metadata;

    return step;
}

static ue_relay_route *create_route_from_args(ue_crypto_metadata *our_crypto_metadata, int argc, char **argv) {
    ue_relay_route *route;
    ue_relay_step **steps;
    int step_number;
    int i, j;

    route = NULL;
    steps = NULL;
    step_number = (argc - 3)/2;
    ue_safe_alloc(steps, ue_relay_step *, step_number);
    ue_safe_alloc(remote_crypto_metadatas, ue_crypto_metadata *, step_number);
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
            ue_crypto_metadata_destroy_all(ue_relay_step_get_target_crypto_metadata(steps[i]));
            ue_relay_step_destroy(steps[i]);
        }
        ue_safe_free(steps);
    }
    return NULL;
}

ue_relay_route *generate_simple_route(ue_crypto_metadata *our_crypto_metadata) {
    ue_relay_route *route;
    ue_crypto_metadata *b_crypto_metadata, *c_crypto_metadata;

    if (!(b_crypto_metadata = ue_crypto_metadata_create_empty())) {
        ei_stacktrace_push_msg("Failed to create empty crypto metadata object for target b");
        return NULL;
    }

    if (!ue_crypto_metadata_read_certificates(b_crypto_metadata, "out/public", "server1_uid")) {
        ue_crypto_metadata_destroy(b_crypto_metadata);
        ei_stacktrace_push_msg("Failed to read certificates of target b");
        return NULL;
    }

    if (!(c_crypto_metadata = ue_crypto_metadata_create_empty())) {
        ei_stacktrace_push_msg("Failed to create empty crypto metadata object for target c");
        return NULL;
    }

    if (!ue_crypto_metadata_read_certificates(c_crypto_metadata, "out/public", "server2_uid")) {
        ue_crypto_metadata_destroy(c_crypto_metadata);
        ei_stacktrace_push_msg("Failed to read certificates of target c");
        return NULL;
    }

    if (!(route = ue_relay_route_create(
        ue_relay_steps_create(
            2,
            ue_relay_step_create(ue_communication_metadata_create_socket_type("127.0.0.1", 5001), our_crypto_metadata, b_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("127.0.0.1", 5002), our_crypto_metadata, c_crypto_metadata)
        ),
        2))) {

        ei_stacktrace_push_msg("Failed to create route A -> B -> C");
        return NULL;
    }

    return route;
}

static bool send_message(ue_byte_stream *message_to_send) {
    bool result;

    ei_check_parameter_or_return(message_to_send);
    ei_check_parameter_or_return(!ue_byte_stream_is_empty(message_to_send));

    result = false;

    uv_mutex_lock(&context.mutex);
    context.transmission_state = WRITING_STATE;
    result = ue_relay_client_send_message(context.client, message_to_send);
    context.transmission_state = READING_STATE;
    uv_cond_signal(&context.cond);
    uv_mutex_unlock(&context.mutex);

    return result;
}

static bool receive_message(ue_byte_stream *received_message) {
    uv_mutex_lock(&context.mutex);
    while (context.transmission_state == WRITING_STATE) {
        uv_cond_wait(&context.cond, &context.mutex);
    }
    uv_mutex_unlock(&context.mutex);

    return ue_relay_client_receive_message(context.client, received_message);
}

/*static bool send_cipher_message(ue_channel_client *channel_client, void *connection, ue_byte_stream *message_to_send) {
    bool result;
    unsigned char *cipher_data;
    size_t cipher_data_size;
    ue_x509_certificate *server_certificate;
    ue_public_key *server_public_key;

    result = false;
    cipher_data = NULL;
    server_public_key = NULL;

    if (!(server_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(context.cipher_keystore, (const unsigned char *)"CIPHER_SERVER", strlen("CIPHER_SERVER")))) {
        ei_stacktrace_push_msg("Failed to get cipher client certificate");
        goto clean_up;
    }

    if (!(server_public_key = ue_rsa_public_key_from_x509_certificate(server_certificate))) {
        ei_stacktrace_push_msg("Failed to get server public key from server certificate");
        goto clean_up;
    }

    if (!ue_cipher_plain_data(ue_byte_stream_get_data(message_to_send), ue_byte_stream_get_size(message_to_send),
        server_public_key, context.signer_keystore->private_key, &cipher_data, &cipher_data_size, context.cipher_name,
        context.digest_name)) {

        ei_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

    ue_byte_stream_clean_up(context.message_to_send);

    if (!ue_byte_writer_append_bytes(context.message_to_send, cipher_data, cipher_data_size)) {
        ei_stacktrace_push_msg("Failed to write cipher data to message to send");
        goto clean_up;
    }

    if (!send_message(channel_client, connection, context.message_to_send)) {
        ei_stacktrace_push_msg("Failed to send cipher message");
        goto clean_up;
    }

    result = true;

clean_up:
    ue_safe_free(cipher_data);
    ue_public_key_destroy(server_public_key);
    return result;
}

static size_t receive_cipher_message(ue_channel_client *channel_client, void *connection) {
    unsigned char *plain_data;
    size_t received, plain_data_size;
    ue_x509_certificate *server_certificate;
    ue_public_key *server_public_key;

    plain_data = NULL;
    server_public_key = NULL;

    received = receive_message(channel_client, connection);

    if (received <= 0 || received == ULLONG_MAX) {
        ei_logger_warn("Connection with server is interrupted.");
        goto clean_up;
    }

    if (!(server_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(context.signer_keystore, (const unsigned char *)"SIGNER_SERVER", strlen("SIGNER_SERVER")))) {
        ei_stacktrace_push_msg("Failed to find server signer certificate");
        received = -1;
        goto clean_up;
    }

    if (!(server_public_key = ue_rsa_public_key_from_x509_certificate(server_certificate))) {
        ei_stacktrace_push_msg("Failed to get server public key from server certificate");
        received = -1;
        goto clean_up;
    }

    if (!ue_decipher_cipher_data(ue_byte_stream_get_data(context.received_message),
        ue_byte_stream_get_size(context.received_message), context.cipher_keystore->private_key,
        server_public_key, &plain_data, &plain_data_size, context.cipher_name,
        context.digest_name)) {

        received = -1;
        ei_stacktrace_push_msg("Failed decipher message data");
        goto clean_up;
    }

    ue_byte_stream_clean_up(context.received_message);

    if (!ue_byte_writer_append_bytes(context.received_message, plain_data, plain_data_size)) {
        received = -1;
        ei_stacktrace_push_msg("Failed to write plain data to received message");
        goto clean_up;
    }

clean_up:
    ue_public_key_destroy(server_public_key);
    ue_safe_free(plain_data);
    return received;
}*/

static void read_consumer(void *parameter) {
    ue_byte_stream *received_message;

    received_message = ue_byte_stream_create();

    while (context.running) {
        if (!receive_message(received_message)) {
            ei_logger_stacktrace("Failed to receive message");
            ei_stacktrace_clean_up();
        }
        ue_byte_stream_print_string(received_message, stdout);
        if (memcmp(ue_byte_stream_get_data(received_message), "-s", strlen("-s")) == 0) {
            context.running = false;
            break;
        }
    }

    ue_byte_stream_destroy(received_message);
}

static void write_consumer(void *parameter) {
    char *input;
    ue_byte_stream *message;

    if (!(message = ue_byte_stream_create())) {
        ei_stacktrace_push_msg("Failed to create empty byte stream");
        return;
    }

    while (context.running) {
        input = ue_input_string(">");

        if (!input) {
            continue;
        }

        if (strcmp(input, "-q") == 0) {
            context.running = false;
            break;
        }

        ue_byte_stream_clean_up(message);
        ue_byte_writer_append_string(message, input);

        if (!send_message(message)) {
            ei_logger_stacktrace("Failed to send message to server");
        } else {
            ei_logger_info("Message sent.");
        }

        ue_safe_free(input);
    }

    ue_safe_free(input);
    ue_byte_stream_destroy(message);
}

int main(int argc, char **argv) {
    ue_relay_route *route;
    ue_crypto_metadata *our_crypto_metadata;
    int i;

    route = NULL;
    our_crypto_metadata = NULL;
    remote_crypto_metadatas = NULL;
    remote_crypto_metadatas_number = 0;

    if (argc < 4) {
        fprintf(stdout, "Usage: %s <client_uid> <client_password> <server_uid> <server_port> [server_uid server_port ...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ei_logger_info("UnknownEchoLib is correctly initialized.");

    uv_mutex_init(&context.mutex);
    uv_cond_init(&context.cond);
    context.client = NULL;
    context.transmission_state = WRITING_STATE;
    context.running = true;

    if (!(our_crypto_metadata = ue_crypto_metadata_write_if_not_exist("out/private", "out/public", argv[1], argv[2]))) {
        ei_stacktrace_push_msg("Failed to get crypto metadata");
        goto clean_up;
    }

    if (!(route = create_route_from_args(our_crypto_metadata, argc, argv))) {
        ei_stacktrace_push_msg("Failed to create route from args");
        goto clean_up;
    }

    //route = generate_simple_route(our_crypto_metadata);

    if (!ue_relay_route_is_valid(route)) {
        ei_stacktrace_push_msg("New route is invalid");
        goto clean_up;
    }

    if (!(context.client = ue_relay_client_create_from_route(route))) {
        ei_stacktrace_push_msg("Failed to create new relay client");
        goto clean_up;
    }

    if (!ue_relay_client_is_valid(context.client)) {
        ei_stacktrace_push_msg("New relay client is invalid");
        goto clean_up;
    }
    ei_logger_info("New relay client is valid");

    uv_thread_create(&context.read_consumer_thread, read_consumer, NULL);
    uv_thread_create(&context.write_consumer_thread, write_consumer, NULL);

    uv_thread_join(&context.read_consumer_thread);
    uv_thread_join(&context.write_consumer_thread);

clean_up:
    ue_relay_client_destroy(context.client);
    uv_mutex_destroy(&context.mutex);
    uv_cond_destroy(&context.cond);
    ue_crypto_metadata_destroy_all(our_crypto_metadata);
    ue_relay_route_destroy(route);
    if (remote_crypto_metadatas) {
        for (i = 0; i < remote_crypto_metadatas_number; i++) {
            ue_crypto_metadata_destroy_all(remote_crypto_metadatas[i]);
        }
        ue_safe_free(remote_crypto_metadatas);
    }
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
