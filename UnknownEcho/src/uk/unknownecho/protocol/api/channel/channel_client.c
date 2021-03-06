/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <uk/unknownecho/protocol/api/channel/channel_client.h>
#include <uk/unknownecho/protocol/api/channel/channel_message_type.h>
#include <uk/unknownecho/network/api/communication/communication.h>
#include <uk/unknownecho/network/api/communication/communication_secure_layer.h>
#include <uk/unknownecho/network/factory/communication_factory.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/uecm.h>
#include <uk/utils/ei.h>

#include <string.h>
#include <limits.h>


typedef struct {
    unsigned char *data;
    size_t size;
} pushed_message;


static uk_ue_channel_client **channel_clients = NULL;
static int max_channel_clients_number = 0;


#if defined(_WIN32)
    #include <windows.h>
#elif defined(__unix__)
    #include <unistd.h>
    #include <sys/socket.h>
#endif


#define CSR_SERVER_CERTIFICATE_FILE_NAME    "csr_server.pem"
#define CSL_SERVER_CERTIFICATE_FILE_NAME    "csl_server.pem"
#define CIPHER_SERVER_CERTIFICATE_FILE_NAME "cipher_server.pem"
#define SIGNER_SERVER_CERTIFICATE_FILE_NAME "signer_server.pem"
#define CSL_KEYSTORE_PATH                   "/keystore/csl_client_keystore.p12"
#define CIPHER_KEYSTORE_PATH                "/keystore/cipher_client_keystore.p12"
#define SIGNER_KEYSTORE_PATH                "/keystore/signer_client_keystore.p12"
#define LOGGER_FILE_NAME                    "logs.txt"


static bool send_message(uk_ue_channel_client *channel_client, void *connection, uk_utils_byte_stream *message_to_send);

static size_t receive_message(uk_ue_channel_client *channel_client, void *connection);

static bool send_cipher_message(uk_ue_channel_client *channel_client, void *connection, uk_utils_byte_stream *message_to_send);

static size_t receive_cipher_message(uk_ue_channel_client *channel_client, void *connection);

static bool create_keystores(uk_ue_channel_client *channel_client, const char *csr_server_host, unsigned short int csr_server_port, char *keystore_password);

static bool process_csr_response(uk_ue_channel_client *channel_client, uk_utils_byte_stream *received_message);

static bool process_csr_request(uk_ue_channel_client *channel_client, uk_crypto_csr_context *context, int csr_sub_type);

static bool process_user_input(uk_ue_channel_client *channel_client, void *connection,
    unsigned char *data, size_t data_size);

static void csl_read_consumer(void *parameter);

static void csl_write_consumer_stdin(void *parameter);

static void csl_write_consumer_push(void *parameter);

static bool process_get_certificate_request(uk_ue_channel_client *channel_client, uk_crypto_pkcs12_keystore *keystore,
    void *connection, const unsigned char *friendly_name, size_t friendly_name_size);

static bool process_channel_key_request(uk_ue_channel_client *channel_client, void *connection,
    uk_utils_byte_stream *request);

static bool send_nickname_request(uk_ue_channel_client *channel_client, void *connection);

static bool process_message_request(uk_ue_channel_client *channel_client, void *connection,
    unsigned char *data, size_t data_size);

static bool process_nickname_response(uk_ue_channel_client *channel_client, uk_utils_byte_stream *response);

static bool process_channel_connection_response(uk_ue_channel_client *channel_client, uk_utils_byte_stream *response);

static bool process_message_response(uk_ue_channel_client *channel_client, uk_utils_byte_stream *message);

static bool process_certificate_response(uk_ue_channel_client *channel_client, uk_utils_byte_stream *response);

static bool process_channel_key_response(uk_ue_channel_client *channel_client, void *connection,
    uk_utils_byte_stream *response);

static bool generate_certificate(uk_crypto_x509_certificate **certificate, uk_crypto_private_key **private_key);


bool uk_ue_channel_client_init(int channel_clients_number) {
    int i;

    uk_utils_check_parameter_or_return(channel_clients_number > 0);

    channel_clients = NULL;
    max_channel_clients_number = channel_clients_number;

    uk_utils_safe_alloc(channel_clients, uk_ue_channel_client *, max_channel_clients_number);
    for (i = 0; i < max_channel_clients_number; i++) {
        channel_clients[i] = NULL;
    }

    return true;
}

void uk_ue_channel_client_uninit() {
    uk_utils_safe_free(channel_clients);
}

static int get_available_channel_client_index() {
    int i;

    for (i = 0; i < max_channel_clients_number; i++) {
        if (!channel_clients[i]) {
            return i;
        }
    }

    return -1;
}

uk_ue_channel_client *uk_ue_channel_client_create(char *persistent_path, char *nickname, const char *csr_server_host, int csr_server_port,
    const char *csl_server_host, int csl_server_port, char *keystore_password, const char *server_certificates_path, void *user_context,
    bool (*write_callback)(void *user_context, uk_utils_byte_stream *printer), bool (*initialization_begin_callback)(void *user_context),
    bool (*initialization_end_callback)(void *user_context), bool (*uninitialization_begin_callback)(void *user_context),
    bool (*uninitialization_end_callback)(void *user_context), bool (*connection_begin_callback)(void *user_context),
    bool (*connection_end_callback)(void *user_context), char *(*user_input_callback)(void *user_context),
    const char *cipher_name, const char *digest_name, uk_utils_user_input_mode user_input_mode, uk_ue_communication_type communication_type) {

    uk_ue_channel_client *channel_client;
    bool result;
    char *keystore_folder_path, *logs_file_name, *full_persistent_path;
    int available_channel_client_index;

    uk_utils_check_parameter_or_return(persistent_path);
    uk_utils_check_parameter_or_return(nickname);
    uk_utils_check_parameter_or_return(csr_server_host);
    uk_utils_check_parameter_or_return(csr_server_port > 0);
    if (csr_server_port <= 1024) {
        uk_utils_logger_warn("CSR server port set to %d but it would be better if it > 1024");
    }
    uk_utils_check_parameter_or_return(csl_server_host);
    uk_utils_check_parameter_or_return(csl_server_port > 0);
    if (csl_server_port <= 1024) {
        uk_utils_logger_warn("CSL server port set to %d but it would be better if it > 1024");
    }

    result = false;
    keystore_folder_path = NULL;
    logs_file_name = NULL;
    full_persistent_path = NULL;

    if ((available_channel_client_index = get_available_channel_client_index()) == -1) {
        uk_utils_stacktrace_push_msg("No such channel client slot available")
        return NULL;
    }

    channel_clients[available_channel_client_index] = NULL;

    uk_utils_safe_alloc(channel_clients[available_channel_client_index], uk_ue_channel_client, 1);
    channel_client = channel_clients[available_channel_client_index];
    channel_client->connection = NULL;
    channel_client->new_message = NULL;
    channel_client->running = false;
    channel_client->nickname = NULL;
    channel_client->communication_secure_layer_session = NULL;
    channel_client->channel_id = -1;
    channel_client->keystore_password = NULL;
    channel_client->csl_keystore_ok = false;
    channel_client->cipher_keystore_ok = false;
    channel_client->signer_keystore_ok = false;
    channel_client->csl_csr_context = NULL;
    channel_client->cipher_csr_context = NULL;
    channel_client->signer_csr_context = NULL;
    channel_client->csl_keystore = NULL;
    channel_client->cipher_keystore = NULL;
    channel_client->signer_keystore = NULL;
    channel_client->channel_key = NULL;
    channel_client->channel_iv = NULL;
    channel_client->channel_iv_size = 0;
    channel_client->persistent_path = NULL;
    channel_client->csl_server_host = NULL;
    channel_client->write_callback = write_callback;
    channel_client->initialization_begin_callback = initialization_begin_callback;
    channel_client->initialization_end_callback = initialization_end_callback;
    channel_client->connection_begin_callback = connection_begin_callback;
    channel_client->connection_end_callback = connection_end_callback;
    channel_client->user_input_callback = user_input_callback;
    channel_client->user_context = user_context;
    channel_client->csr_processing_state = FREE_STATE;
    channel_client->user_input_mode = user_input_mode;
    channel_client->communication_context = uk_ue_communication_build_from_type(communication_type);
    channel_client->received_message = uk_utils_byte_stream_create();
    channel_client->message_to_send = uk_utils_byte_stream_create();
    channel_client->tmp_stream = uk_utils_byte_stream_create();

    if (channel_client->initialization_begin_callback) {
        channel_client->initialization_begin_callback(channel_client->user_context);
    }

    channel_client->mutex = uk_utils_thread_mutex_create();

    channel_client->cond = uk_utils_thread_cond_create();

    if (!(channel_client->push_mode_queue = uk_utils_queuk_ue_create())) {
        uk_utils_stacktrace_push_msg("Failed to create push mode queue");
        goto clean_up;
    }

    channel_client->nickname = uk_utils_string_create_from(nickname);
    channel_client->persistent_path = uk_utils_string_create_from(persistent_path);
    channel_client->csl_server_host = uk_utils_string_create_from(csl_server_host);
    channel_client->csl_server_port = csl_server_port;
    channel_client->cipher_name = uk_utils_string_create_from(cipher_name);
    channel_client->digest_name = uk_utils_string_create_from(digest_name);

    full_persistent_path = uk_utils_strcat_variadic("sss", channel_client->persistent_path, "/", channel_client->nickname);

    uk_utils_create_folder(full_persistent_path);

    logs_file_name = uk_utils_strcat_variadic("sss", full_persistent_path, "/", LOGGER_FILE_NAME);
    channel_client->logs_file = NULL;
    if (!(channel_client->logs_file = fopen(logs_file_name, "a"))) {
        uk_utils_stacktrace_push_msg("Failed to open logs file at path '%s'", logs_file_name)
    }

    uk_utils_logger_set_fp(uk_utils_logger_manager_get_logger(), channel_client->logs_file);

    //uk_utils_logger_set_details(uk_utils_logger_manager_get_logger(), true);

    channel_client->csr_server_certificate_path = uk_utils_strcat_variadic("sss", server_certificates_path, "/", CSR_SERVER_CERTIFICATE_FILE_NAME);
    channel_client->csl_server_certificate_path = uk_utils_strcat_variadic("sss", server_certificates_path, "/", CSL_SERVER_CERTIFICATE_FILE_NAME);
    channel_client->cipher_server_certificate_path = uk_utils_strcat_variadic("sss", server_certificates_path, "/", CIPHER_SERVER_CERTIFICATE_FILE_NAME);
    channel_client->signer_server_certificate_path = uk_utils_strcat_variadic("sss", server_certificates_path, "/", SIGNER_SERVER_CERTIFICATE_FILE_NAME);
    channel_client->csl_keystore_path = uk_utils_strcat_variadic("ss", full_persistent_path, CSL_KEYSTORE_PATH);
    channel_client->cipher_keystore_path = uk_utils_strcat_variadic("ss", full_persistent_path, CIPHER_KEYSTORE_PATH);
    channel_client->signer_keystore_path = uk_utils_strcat_variadic("ss", full_persistent_path, SIGNER_KEYSTORE_PATH);

    if (keystore_password) {
        channel_client->keystore_password = uk_utils_string_create_from(keystore_password);
    }

    keystore_folder_path = uk_utils_strcat_variadic("ssss", channel_client->persistent_path, "/", channel_client->nickname, "/keystore");

    if (!uk_utils_is_dir_exists(keystore_folder_path)) {
        uk_utils_logger_info("Creating '%s'...", keystore_folder_path);
        if (!uk_utils_create_folder(keystore_folder_path)) {
            uk_utils_stacktrace_push_msg("Failed to create '%s'", keystore_folder_path);
            goto clean_up;
        }
    }

    if (!uk_crypto_x509_certificate_load_from_file(channel_client->csr_server_certificate_path, &channel_client->csr_server_certificate)) {
        uk_utils_stacktrace_push_msg("Failed to load CSR server certificate from path '%s'", channel_client->csr_server_certificate_path);
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_load_from_file(channel_client->csl_server_certificate_path, &channel_client->csl_server_certificate)) {
        uk_utils_stacktrace_push_msg("Failed to load CSL server certificate from path '%s'", channel_client->csl_server_certificate_path);
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_load_from_file(channel_client->cipher_server_certificate_path, &channel_client->cipher_server_certificate)) {
        uk_utils_stacktrace_push_msg("Failed to load cipher server certificate from path '%s'", channel_client->cipher_server_certificate_path);
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_load_from_file(channel_client->signer_server_certificate_path, &channel_client->signer_server_certificate)) {
        uk_utils_stacktrace_push_msg("Failed to load signer server certificate from path '%s'", channel_client->signer_server_certificate_path);
        goto clean_up;
    }

    if (!create_keystores(channel_client, csr_server_host, csr_server_port, channel_client->keystore_password)) {
        uk_utils_stacktrace_push_msg("Failed to create keystore");
        goto clean_up;
    }

    result = true;

clean_up:
    if (channel_client->initialization_end_callback) {
        channel_client->initialization_end_callback(channel_client->user_context);
    }
    uk_utils_safe_free(keystore_folder_path);
    uk_utils_safe_free(logs_file_name);
    uk_utils_safe_free(full_persistent_path);
    if (!result) {
        uk_ue_channel_client_destroy(channel_client);
        channel_client = NULL;
    }
    return channel_client;
}

void uk_ue_channel_client_destroy(uk_ue_channel_client *channel_client) {
    if (!channel_client) {
        return;
    }
    if (channel_client->uninitialization_begin_callback) {
        channel_client->uninitialization_begin_callback(channel_client->user_context);
    }
    uk_utils_thread_mutex_destroy(channel_client->mutex);
    uk_utils_thread_cond_destroy(channel_client->cond);
    if (channel_client->communication_secure_layer_session) {
        uk_ue_communication_secure_layer_destroy(channel_client->communication_context, channel_client->communication_secure_layer_session);
    }
    uk_utils_byte_stream_destroy(channel_client->new_message);
    uk_utils_safe_str_free(channel_client->nickname)
    uk_utils_safe_str_free(channel_client->keystore_password);
    if (channel_client->connection) {
        uk_ue_communication_client_connection_destroy(channel_client->communication_context, channel_client->connection);
    }
    uk_crypto_x509_certificate_destroy(channel_client->csr_server_certificate);
    uk_crypto_x509_certificate_destroy(channel_client->csl_server_certificate);
    uk_crypto_x509_certificate_destroy(channel_client->cipher_server_certificate);
    uk_crypto_x509_certificate_destroy(channel_client->signer_server_certificate);
    if (channel_client->csl_csr_context) {
        uk_crypto_sym_key_destroy(channel_client->csl_csr_context->future_key);
        uk_utils_safe_free(channel_client->csl_csr_context->iv);
        uk_utils_safe_free(channel_client->csl_csr_context);
    }
    if (channel_client->cipher_csr_context) {
        uk_crypto_sym_key_destroy(channel_client->cipher_csr_context->future_key);
        uk_utils_safe_free(channel_client->cipher_csr_context->iv);
        uk_utils_safe_free(channel_client->cipher_csr_context);
    }
    if (channel_client->signer_csr_context) {
        uk_crypto_sym_key_destroy(channel_client->signer_csr_context->future_key);
        uk_utils_safe_free(channel_client->signer_csr_context->iv);
        uk_utils_safe_free(channel_client->signer_csr_context);
    }
    //uk_crypto_pkcs12_keystore_destroy(channel_client->csl_keystore);
    //uk_crypto_pkcs12_keystore_destroy(channel_client->cipher_keystore);
    //uk_crypto_pkcs12_keystore_destroy(channel_client->signer_keystore);
    uk_utils_safe_free(channel_client->csr_server_certificate_path);
    uk_utils_safe_free(channel_client->csl_server_certificate_path);
    uk_utils_safe_free(channel_client->cipher_server_certificate_path);
    uk_utils_safe_free(channel_client->signer_server_certificate_path);
    uk_utils_safe_free(channel_client->csl_keystore_path);
    uk_utils_safe_free(channel_client->cipher_keystore_path);
    uk_utils_safe_free(channel_client->signer_keystore_path);
    uk_crypto_sym_key_destroy(channel_client->channel_key);
    uk_utils_safe_free(channel_client->channel_iv);
    uk_utils_safe_free(channel_client->persistent_path);
    uk_utils_safe_free(channel_client->csl_server_host);
    uk_utils_safe_free(channel_client->cipher_name);
    uk_utils_safe_free(channel_client->digest_name);
    uk_utils_queuk_ue_destroy(channel_client->push_mode_queue);
    uk_utils_byte_stream_destroy(channel_client->received_message);
    uk_utils_byte_stream_destroy(channel_client->message_to_send);
    uk_utils_byte_stream_destroy(channel_client->tmp_stream);
    uk_ue_communication_destroy(channel_client->communication_context);
    if (channel_client->uninitialization_end_callback) {
        channel_client->uninitialization_end_callback(channel_client->user_context);
    }
    uk_utils_safe_fclose(channel_client->logs_file);
    uk_utils_logger_set_fp(uk_utils_logger_manager_get_logger(), NULL);
    uk_utils_safe_free(channel_client);
}

bool uk_ue_channel_client_start(uk_ue_channel_client *channel_client) {
    void *client_connection_parameters;
    uk_crypto_x509_certificate **ca_certificates;

    uk_utils_check_parameter_or_return(channel_client->csl_server_host);
    uk_utils_check_parameter_or_return(channel_client->csl_server_port > 0);

    ca_certificates = NULL;
    client_connection_parameters = NULL;

    uk_utils_safe_alloc(ca_certificates, uk_crypto_x509_certificate *, 1);
    ca_certificates[0] = channel_client->csl_server_certificate;

    if (channel_client->connection_begin_callback) {
        channel_client->connection_begin_callback(channel_client->user_context);
    }

    /* @todo pass keystore ptr instead of path */
    if (!(channel_client->communication_secure_layer_session = uk_ue_communication_secure_layer_build_client(
        channel_client->communication_context, 4, (char *)channel_client->csl_keystore_path,
        channel_client->keystore_password, ca_certificates, 1))) {

        uk_utils_stacktrace_push_msg("Failed to create CSL session");
        if (channel_client->connection_end_callback) {
            channel_client->connection_end_callback(channel_client->user_context);
        }
        return false;
    }

    uk_utils_safe_free(ca_certificates);

    if (!(client_connection_parameters = uk_ue_communication_build_client_connection_parameters(
        channel_client->communication_context, 3, channel_client->csl_server_host,
        channel_client->csl_server_port, channel_client->communication_secure_layer_session))) {

        uk_utils_stacktrace_push_msg("Failed to build client connection parameters context");
        if (channel_client->connection_end_callback) {
            channel_client->connection_end_callback(channel_client->user_context);
        }
        return false;
    }

    if (!(channel_client->connection = uk_ue_communication_connect(channel_client->communication_context,
        client_connection_parameters))) {

        uk_utils_stacktrace_push_msg("Failed to connect socket to server");
        if (channel_client->connection_end_callback) {
            channel_client->connection_end_callback(channel_client->user_context);
        }
        uk_utils_safe_free(client_connection_parameters);
        return false;
    }
    uk_utils_safe_free(client_connection_parameters);

    channel_client->running = true;
    channel_client->transmission_state = WRITING_STATE;
    channel_client->new_message = uk_utils_byte_stream_create();
    channel_client->channel_id = -1;
    uk_ue_communication_client_connection_set_user_data(channel_client->communication_context,
        channel_client->connection, channel_client);

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wpedantic\"")
    channel_client->read_thread = uk_utils_thread_create(csl_read_consumer, channel_client);
    if (channel_client->user_input_mode == UnknownKrakenUtils_STDIN_INPUT) {
        channel_client->write_thread = uk_utils_thread_create(csl_write_consumer_stdin, channel_client);
    } else if (channel_client->user_input_mode == UnknownKrakenUtils_PUSH_INPUT) {
        channel_client->write_thread = uk_utils_thread_create(csl_write_consumer_push, channel_client);
    } else {
        uk_utils_stacktrace_push_msg("Unknown user input mode");
        return false;
    }
_Pragma("GCC diagnostic pop")

    if (channel_client->connection_end_callback) {
        channel_client->connection_end_callback(channel_client->user_context);
    }

    uk_utils_thread_join(channel_client->read_thread, NULL);
    uk_utils_thread_join(channel_client->write_thread, NULL);

    return true;
}

void uk_ue_channel_client_shutdown_signal_callback(int sig) {
    int i;

    uk_utils_logger_trace("Signal received %d", sig);

    for (i = 0; i < max_channel_clients_number; i++) {
        if (!channel_clients[i]) {
            continue;
        }
        uk_utils_logger_info("Shuting down client #%d...", i);
        channel_clients[i]->running = false;
        channel_clients[i]->transmission_state = CLOSING_STATE;
        uk_utils_thread_cond_signal(channel_clients[i]->cond);
        uk_utils_thread_cancel(channel_clients[i]->read_thread);
    }
}

bool uk_ue_channel_client_set_user_input_mode(uk_ue_channel_client *channel_client, uk_utils_user_input_mode mode) {
    channel_client->user_input_mode = mode;
    return true;
}

bool uk_ue_channel_client_push_message(uk_ue_channel_client *channel_client, unsigned char *data, size_t data_size) {
    pushed_message message;
    message.data = data;
    message.size = data_size;

    return uk_utils_queuk_ue_push_wait(channel_client->push_mode_queue, &message);
}

static bool send_message(uk_ue_channel_client *channel_client, void *connection, uk_utils_byte_stream *message_to_send) {
    size_t sent;

    uk_utils_check_parameter_or_return(connection);
    uk_utils_check_parameter_or_return(message_to_send);
    uk_utils_check_parameter_or_return(uk_utils_byte_stream_get_size(message_to_send) > 0);

    uk_utils_thread_mutex_lock(channel_client->mutex);
    channel_client->transmission_state = WRITING_STATE;
    sent = uk_ue_communication_send_sync(channel_client->communication_context, connection, message_to_send);
    channel_client->transmission_state = READING_STATE;
    uk_utils_thread_cond_signal(channel_client->cond);
    uk_utils_thread_mutex_unlock(channel_client->mutex);

    if (sent == 0 || sent == ULLONG_MAX) {
        uk_utils_logger_info("Connection is interrupted.");
        uk_utils_stacktrace_push_msg("Failed to send message to server");
        channel_client->running = false;
        return false;
    }

    return true;
}

static size_t receive_message(uk_ue_channel_client *channel_client, void *connection) {
    size_t received;

    uk_utils_thread_mutex_lock(channel_client->mutex);
    while (channel_client->transmission_state == WRITING_STATE) {
        uk_utils_thread_cond_wait(channel_client->cond, channel_client->mutex);
    }
    uk_utils_thread_mutex_unlock(channel_client->mutex);
    uk_utils_byte_stream_clean_up(channel_client->received_message);
    received = uk_ue_communication_receive_sync(channel_client->communication_context, connection,
        channel_client->received_message);

    return received;
}

static bool send_cipher_message(uk_ue_channel_client *channel_client, void *connection, uk_utils_byte_stream *message_to_send) {
    bool result;
    unsigned char *cipher_data;
    size_t cipher_data_size;
    uk_crypto_x509_certificate *server_certificate;
    uk_crypto_public_key *server_public_key;

    result = false;
    cipher_data = NULL;
    server_public_key = NULL;

    if (!(server_certificate = uk_crypto_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->cipher_keystore, (const unsigned char *)"CIPHER_SERVER", strlen("CIPHER_SERVER")))) {
        uk_utils_stacktrace_push_msg("Failed to get cipher client certificate");
        goto clean_up;
    }

    if (!(server_public_key = uk_crypto_rsa_public_key_from_x509_certificate(server_certificate))) {
        uk_utils_stacktrace_push_msg("Failed to get server public key from server certificate");
        goto clean_up;
    }

    if (!uk_crypto_cipher_plain_data(uk_utils_byte_stream_get_data(message_to_send), uk_utils_byte_stream_get_size(message_to_send),
        server_public_key, channel_client->signer_keystore->private_key, &cipher_data, &cipher_data_size, channel_client->cipher_name,
        channel_client->digest_name)) {

        uk_utils_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

    uk_utils_byte_stream_clean_up(channel_client->message_to_send);

    if (!uk_utils_byte_writer_append_bytes(channel_client->message_to_send, cipher_data, cipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to write cipher data to message to send");
        goto clean_up;
    }

    if (!send_message(channel_client, connection, channel_client->message_to_send)) {
        uk_utils_stacktrace_push_msg("Failed to send cipher message");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_utils_safe_free(cipher_data);
    uk_crypto_public_key_destroy(server_public_key);
    return result;
}

static size_t receive_cipher_message(uk_ue_channel_client *channel_client, void *connection) {
    unsigned char *plain_data;
    size_t received, plain_data_size;
    uk_crypto_x509_certificate *server_certificate;
    uk_crypto_public_key *server_public_key;

    plain_data = NULL;
    server_public_key = NULL;

    received = receive_message(channel_client, connection);

    if (received <= 0 || received == ULLONG_MAX) {
        uk_utils_logger_warn("Connection with server is interrupted.");
        goto clean_up;
    }

    if (!(server_certificate = uk_crypto_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->signer_keystore, (const unsigned char *)"SIGNER_SERVER", strlen("SIGNER_SERVER")))) {
        uk_utils_stacktrace_push_msg("Failed to find server signer certificate");
        received = -1;
        goto clean_up;
    }

    if (!(server_public_key = uk_crypto_rsa_public_key_from_x509_certificate(server_certificate))) {
        uk_utils_stacktrace_push_msg("Failed to get server public key from server certificate");
        received = -1;
        goto clean_up;
    }

    if (!uk_crypto_decipher_cipher_data(uk_utils_byte_stream_get_data(channel_client->received_message),
        uk_utils_byte_stream_get_size(channel_client->received_message), channel_client->cipher_keystore->private_key,
        server_public_key, &plain_data, &plain_data_size, channel_client->cipher_name,
        channel_client->digest_name)) {

        received = -1;
        uk_utils_stacktrace_push_msg("Failed decipher message data");
        goto clean_up;
    }

    uk_utils_byte_stream_clean_up(channel_client->received_message);

    if (!uk_utils_byte_writer_append_bytes(channel_client->received_message, plain_data, plain_data_size)) {
        received = -1;
        uk_utils_stacktrace_push_msg("Failed to write plain data to received message");
        goto clean_up;
    }

clean_up:
    uk_crypto_public_key_destroy(server_public_key);
    uk_utils_safe_free(plain_data);
    return received;
}

static bool create_keystores(uk_ue_channel_client *channel_client, const char *csr_server_host, unsigned short int csr_server_port, char *keystore_password) {
    bool result, csl_keystore_exists, cipher_keystore_exists, signer_keystore_exists;
    void *client_connection_parameters;

    uk_utils_check_parameter_or_return(csr_server_host);
    uk_utils_check_parameter_or_return(csr_server_port > 0);
    uk_utils_check_parameter_or_return(keystore_password);

    result = false;
    client_connection_parameters = NULL;

    csl_keystore_exists = uk_utils_is_file_exists(channel_client->csl_keystore_path);
    cipher_keystore_exists = uk_utils_is_file_exists(channel_client->cipher_keystore_path);
    signer_keystore_exists = uk_utils_is_file_exists(channel_client->signer_keystore_path);

    if (!csl_keystore_exists) {
        uk_utils_safe_alloc(channel_client->csl_csr_context, uk_crypto_csr_context, 1);
        channel_client->csl_csr_context->signed_certificate = NULL;
        channel_client->csl_csr_context->private_key = NULL;
        channel_client->csl_csr_context->future_key = NULL;
        channel_client->csl_csr_context->iv = NULL;
    } else {
        if (!(channel_client->csl_keystore = uk_crypto_pkcs12_keystore_load(channel_client->csl_keystore_path,
            channel_client->keystore_password))) {
            uk_utils_stacktrace_push_msg("Failed to load cipher pkcs12 keystore");
            goto clean_up;
        }
    }

    if (!cipher_keystore_exists) {
        uk_utils_safe_alloc(channel_client->cipher_csr_context, uk_crypto_csr_context, 1);
        channel_client->cipher_csr_context->signed_certificate = NULL;
        channel_client->cipher_csr_context->private_key = NULL;
        channel_client->cipher_csr_context->future_key = NULL;
        channel_client->cipher_csr_context->iv = NULL;
    } else {
        if (!(channel_client->cipher_keystore = uk_crypto_pkcs12_keystore_load(channel_client->cipher_keystore_path, channel_client->keystore_password))) {
            uk_utils_stacktrace_push_msg("Failed to load cipher pkcs12 keystore");
            goto clean_up;
        }
    }

    if (!signer_keystore_exists) {
        uk_utils_safe_alloc(channel_client->signer_csr_context, uk_crypto_csr_context, 1);
        channel_client->signer_csr_context->signed_certificate = NULL;
        channel_client->signer_csr_context->private_key = NULL;
        channel_client->signer_csr_context->future_key = NULL;
        channel_client->signer_csr_context->iv = NULL;
    } else {
        if (!(channel_client->signer_keystore = uk_crypto_pkcs12_keystore_load(channel_client->signer_keystore_path, channel_client->keystore_password))) {
            uk_utils_stacktrace_push_msg("Failed to load signer pkcs12 keystore");
            goto clean_up;
        }
    }

    if (!csl_keystore_exists || !cipher_keystore_exists || !signer_keystore_exists) {
        if (!(client_connection_parameters = uk_ue_communication_build_client_connection_parameters(channel_client->communication_context, 2,
            csr_server_host, csr_server_port))) {
            uk_utils_stacktrace_push_msg("Failed to create client connection parameters context");
            goto clean_up;
        }

        if (!(channel_client->connection = uk_ue_communication_connect(channel_client->communication_context,
            client_connection_parameters))) {
            uk_utils_stacktrace_push_msg("Failed to connect socket to server");
            uk_utils_safe_free(client_connection_parameters);
            goto clean_up;
        }
        uk_utils_safe_free(client_connection_parameters);

        channel_client->running = true;
        channel_client->transmission_state = WRITING_STATE;
        uk_ue_communication_client_connection_set_user_data(channel_client->communication_context,
            channel_client->connection, channel_client);
    }

    if (!csl_keystore_exists) {
        uk_utils_logger_info("CSL keystore doesn't exists. A CSR will be built.");
        if (!process_csr_request(channel_client, channel_client->csl_csr_context, CSR_CSL_REQUEST)) {
            uk_utils_stacktrace_push_msg("Failed to process CSR exchange for CSL");
            goto clean_up;
        }
    } else {
        channel_client->csl_keystore_ok = true;
    }

    if (!cipher_keystore_exists) {
        uk_utils_logger_info("Cipher keystore doesn't exists. A CSR will be built.");
        if (!process_csr_request(channel_client, channel_client->cipher_csr_context, CSR_CIPHER_REQUEST)) {
            uk_utils_stacktrace_push_msg("Failed to process CSR exchange for cipher");
            goto clean_up;
        }
    } else {
        channel_client->cipher_keystore_ok = true;
    }

    if (!signer_keystore_exists) {
        uk_utils_logger_info("Signer keystore doesn't exists. A CSR will be built.");
        if (!process_csr_request(channel_client, channel_client->signer_csr_context, CSR_SIGNER_REQUEST)) {
            uk_utils_stacktrace_push_msg("Failed to process CSR exchange for signer");
            goto clean_up;
        }
    } else {
        channel_client->signer_keystore_ok = true;
    }

    if (!csl_keystore_exists || !cipher_keystore_exists || !signer_keystore_exists) {
        //uk_utils_thread_join(channel_client->read_thread, NULL);
        //uk_utils_thread_join(channel_client->connection->read_messages_consumer_thread, NULL);

        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_logger_stacktrace("An error occurred while processing read_consumer()");
            uk_utils_stacktrace_clean_up();
            goto clean_up;
        }
    }

    if (!csl_keystore_exists) {
        if (uk_crypto_x509_certificate_verify(channel_client->csl_csr_context->signed_certificate,
            channel_client->csl_server_certificate)) {

            uk_utils_logger_info("Certificate is correctly signed by the CA");
        } else {
            uk_utils_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
            goto clean_up;
        }

        if (!(channel_client->csl_keystore = uk_crypto_pkcs12_keystore_create(
            channel_client->csl_csr_context->signed_certificate,
            channel_client->csl_csr_context->private_key, "CSL_CLIENT"))) {

            uk_utils_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
            goto clean_up;
        }

        uk_crypto_pkcs12_keystore_add_certificate_from_file(channel_client->csl_keystore,
            channel_client->csl_server_certificate_path, (const unsigned char *)"CSL_SERVER",
            strlen("CSL_SERVER"));

        if (!uk_crypto_pkcs12_keystore_write(channel_client->csl_keystore, channel_client->csl_keystore_path,
            keystore_password)) {

            uk_utils_stacktrace_push_msg("Failed to write keystore to '%s'", channel_client->csl_keystore_path);
            goto clean_up;
        }

        uk_utils_logger_info("CSL keystore created.");
    }

    if (!cipher_keystore_exists) {
        if (uk_crypto_x509_certificate_verify(channel_client->cipher_csr_context->signed_certificate, channel_client->cipher_server_certificate)) {
            uk_utils_logger_info("Certificate is correctly signed by the CA");
        } else {
            uk_utils_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
            goto clean_up;
        }

        if (!(channel_client->cipher_keystore = uk_crypto_pkcs12_keystore_create(channel_client->cipher_csr_context->signed_certificate, channel_client->cipher_csr_context->private_key,
            "CIPHER_CLIENT"))) {

            uk_utils_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
            goto clean_up;
        }

        uk_crypto_pkcs12_keystore_add_certificate_from_file(channel_client->cipher_keystore, channel_client->cipher_server_certificate_path, (const unsigned char *)"CIPHER_SERVER", strlen("CIPHER_SERVER"));

        if (!uk_crypto_pkcs12_keystore_write(channel_client->cipher_keystore, channel_client->cipher_keystore_path, keystore_password)) {
            uk_utils_stacktrace_push_msg("Failed to write keystore to '%s'", channel_client->cipher_keystore_path);
            goto clean_up;
        }

        uk_utils_logger_info("Cipher keystore created.");
    }

    if (!signer_keystore_exists) {
        if (uk_crypto_x509_certificate_verify(channel_client->signer_csr_context->signed_certificate, channel_client->signer_server_certificate)) {
            uk_utils_logger_info("Certificate is correctly signed by the CA");
        } else {
            uk_utils_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
            goto clean_up;
        }

        if (!(channel_client->signer_keystore = uk_crypto_pkcs12_keystore_create(channel_client->signer_csr_context->signed_certificate, channel_client->signer_csr_context->private_key,
            "SIGNER_CLIENT"))) {

            uk_utils_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
            goto clean_up;
        }

        uk_crypto_pkcs12_keystore_add_certificate_from_file(channel_client->signer_keystore, channel_client->signer_server_certificate_path, (const unsigned char *)"SIGNER_SERVER", strlen("SIGNER_SERVER"));

        if (!uk_crypto_pkcs12_keystore_write(channel_client->signer_keystore, channel_client->signer_keystore_path, keystore_password)) {
            uk_utils_stacktrace_push_msg("Failed to write keystore to '%s'", channel_client->signer_keystore_path);
            goto clean_up;
        }

        uk_utils_logger_info("Signer keystore created.");
    }

    result = true;

clean_up:
    return result;
}

static bool process_csr_response(uk_ue_channel_client *channel_client, uk_utils_byte_stream *received_message) {
    bool result;
    int csr_sub_type, csr_response_size;
    unsigned char *csr_response;

    result = false;
    csr_response = NULL;

    uk_utils_byte_stream_set_position(received_message, 0);

    if (!uk_utils_byte_read_next_int(received_message, &csr_sub_type)) {
        uk_utils_stacktrace_push_msg("Failed to read CSR sub type in response");
        goto clean_up;
    }

    if (csr_sub_type != CSR_CSL_RESPONSE &&
        csr_sub_type != CSR_CIPHER_RESPONSE &&
        csr_sub_type != CSR_SIGNER_RESPONSE) {
        uk_utils_logger_warn("Invalid CSR sub type");
        goto clean_up;
    }

    if (!uk_utils_byte_read_next_int(received_message, &csr_response_size)) {
        uk_utils_stacktrace_push_msg("Failed to read CSR response size in response");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_bytes(received_message, &csr_response, (size_t)csr_response_size)) {
        uk_utils_stacktrace_push_msg("Failed to read CSR response in response");
        goto clean_up;
    }

    if (csr_sub_type == CSR_CSL_RESPONSE) {
        uk_utils_logger_trace("Received CSR_CSL_RESPONSE");

        if (!(channel_client->csl_csr_context->signed_certificate = uk_crypto_csr_process_server_response(csr_response,
            (size_t)csr_response_size, channel_client->csl_csr_context->future_key,
            channel_client->csl_csr_context->iv, channel_client->csl_csr_context->iv_size))) {

            uk_utils_stacktrace_push_msg("Failed to process CSR CSL response");
        } else {
            channel_client->csl_keystore_ok = true;
        }
    }
    else if (csr_sub_type == CSR_CIPHER_RESPONSE) {
        uk_utils_logger_trace("Received CSR_CIPHER_RESPONSE");

        if (!(channel_client->cipher_csr_context->signed_certificate = uk_crypto_csr_process_server_response(csr_response,
            (size_t)csr_response_size, channel_client->cipher_csr_context->future_key, channel_client->cipher_csr_context->iv,
            channel_client->cipher_csr_context->iv_size))) {

            uk_utils_stacktrace_push_msg("Failed to process CSR CIPHER response");
        } else {
            channel_client->cipher_keystore_ok = true;
        }
    }
    else if (csr_sub_type == CSR_SIGNER_RESPONSE) {
        uk_utils_logger_trace("Received CSR_SIGNER_RESPONSE");

        if (!(channel_client->signer_csr_context->signed_certificate = uk_crypto_csr_process_server_response(csr_response,
            (size_t)csr_response_size, channel_client->signer_csr_context->future_key, channel_client->signer_csr_context->iv,
            channel_client->signer_csr_context->iv_size))) {

            uk_utils_stacktrace_push_msg("Failed to process CSR SIGNER response");
        } else {
            channel_client->signer_keystore_ok = true;
        }
    }

    result = true;

clean_up:
    uk_utils_safe_free(csr_response);
    return result;
}

static bool process_csr_request(uk_ue_channel_client *channel_client, uk_crypto_csr_context *context, int csr_sub_type) {
    bool result;
    uk_crypto_x509_certificate *certificate;
    size_t csr_request_size;
    unsigned char *csr_request;
    uk_utils_byte_stream *stream;
    uk_crypto_public_key *ca_public_key;

    uk_utils_check_parameter_or_return(channel_client);
    uk_utils_check_parameter_or_return(channel_client->connection);
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(csr_sub_type == CSR_CSL_REQUEST || csr_sub_type == CSR_CIPHER_REQUEST || csr_sub_type == CSR_SIGNER_REQUEST);

    result = false;
    certificate = NULL;
    csr_request = NULL;
    stream = uk_utils_byte_stream_create();
    ca_public_key = NULL;

    uk_utils_logger_trace("Generating crypto random future key...");
    if (!(context->future_key = uk_crypto_sym_key_create_random())) {
        uk_utils_stacktrace_push_msg("Failed to gen random sym key for server response encryption");
        goto clean_up;
    }

    uk_utils_logger_trace("Generating crypto random IV...");
    /* @todo get correct IV size with a function */
    uk_utils_safe_alloc(context->iv, unsigned char, 16);
    if (!(uk_crypto_crypto_random_bytes(context->iv, 16))) {
        uk_utils_stacktrace_push_msg("Failed to get crypto random bytes for IV");
        goto clean_up;
    }
    context->iv_size = 16;

    uk_utils_logger_trace("Extracting RSA public key from CSR X509 server certificate...");
    if (!(ca_public_key = uk_crypto_rsa_public_key_from_x509_certificate(channel_client->csr_server_certificate))) {
        uk_utils_stacktrace_push_msg("Failed to extract RSA public key from CA certificate");
        goto clean_up;
    }

    uk_utils_logger_info("Generating new certificate and private key...");
    if (!generate_certificate(&certificate, &context->private_key)) {
        uk_utils_stacktrace_push_msg("Failed to generate x509 certificate and private key");
        goto clean_up;
    }

    uk_utils_logger_trace("Building CSR request...");
    if (!(csr_request = uk_crypto_csr_build_client_request(certificate, context->private_key, ca_public_key, &csr_request_size, context->future_key, context->iv,
        context->iv_size, channel_client->cipher_name, channel_client->digest_name))) {

        uk_utils_stacktrace_push_msg("Failed to build CSR request");
        goto clean_up;
    }

    if (!uk_utils_byte_writer_append_int(stream, csr_sub_type)) {
        uk_utils_stacktrace_push_msg("Failed to write CSR sub type to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(stream, (int)strlen(channel_client->nickname))) {
        uk_utils_stacktrace_push_msg("Failed to write nickname size to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(stream, (unsigned char *)channel_client->nickname, strlen(channel_client->nickname))) {
        uk_utils_stacktrace_push_msg("Failed to write nickname to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(stream, (int)csr_request_size)) {
        uk_utils_stacktrace_push_msg("Failed to write cipher data size to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(stream, csr_request, csr_request_size)) {
        uk_utils_stacktrace_push_msg("Failed to write CSR request to stream");
        goto clean_up;
    }

    uk_utils_byte_stream_clean_up(channel_client->message_to_send);
    if (!uk_utils_byte_writer_append_bytes(channel_client->message_to_send, uk_utils_byte_stream_get_data(stream), uk_utils_byte_stream_get_size(stream))) {
        uk_utils_stacktrace_push_msg("Failed to write stream data to message to send");
        goto clean_up;
    }

    uk_utils_logger_info("Sending CSR...");
    if (!send_message(channel_client, channel_client->connection, channel_client->message_to_send)) {
        uk_utils_stacktrace_push_msg("Failed to send message to send");
        goto clean_up;
    }

    uk_utils_byte_stream_clean_up(channel_client->received_message);
    if (!receive_message(channel_client, channel_client->connection)) {
        uk_utils_stacktrace_push_msg("Failed to receive CSR response from server, connection was interrupted");
        goto clean_up;
    }

    if (!process_csr_response(channel_client, channel_client->received_message)) {
        uk_utils_stacktrace_push_msg("Failed to process CSR response");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_utils_safe_free(csr_request);
    uk_utils_byte_stream_destroy(stream);
    uk_crypto_public_key_destroy(ca_public_key);
    uk_crypto_x509_certificate_destroy(certificate);
    return result;
}

static bool process_user_input(uk_ue_channel_client *channel_client, void *connection,
    unsigned char *data, size_t data_size) {

    bool result;
    int channel_id;
    char *string_data;

    result = false;
    channel_id = -1;
    string_data = NULL;

    uk_utils_byte_stream_clean_up(channel_client->message_to_send);
    if (!uk_utils_byte_writer_append_int(channel_client->message_to_send, channel_client->channel_id)) {
        uk_utils_stacktrace_push_msg("Failed to write channel id to message to send");
        goto clean_up;
    }

    if (memcmp(data, "-q", data_size) == 0) {
        if (!uk_utils_byte_writer_append_int(channel_client->message_to_send, DISCONNECTION_NOW_REQUEST)) {
            uk_utils_stacktrace_push_msg("Failed to write DISCONNECTION_NOW_REQUEST type to message to send");
            goto clean_up;
        }
        if (!(result = send_cipher_message(channel_client, connection, channel_client->message_to_send))) {
            uk_utils_stacktrace_push_msg("Failed to send cipher message");
            goto clean_up;
        }
        channel_client->running = false;
    }
    else if (uk_utils_bytes_starts_with(data, data_size, (unsigned char *)"@channel_connection", strlen("@channel_connection"))) {
        string_data = uk_utils_string_create_from_bytes(data, data_size);
        if (!uk_utils_string_to_int(string_data + strlen("@channel_connection") + 1, &channel_id, 10)) {
            uk_utils_logger_warn("Specified channel id is invalid. Usage : --channel <number>");
        }
        else if (channel_id == -1) {
            uk_utils_logger_warn("Specified channel id is invalid. It have to be >= 0");
        }
        else {
            if (!uk_utils_byte_writer_append_int(channel_client->message_to_send, CHANNEL_CONNECTION_REQUEST)) {
                uk_utils_stacktrace_push_msg("Failed to write CHANNEL_CONNECTION_REQUEST type to message to send");
                goto clean_up;
            }
            if (!uk_utils_byte_writer_append_int(channel_client->message_to_send, channel_id)) {
                uk_utils_stacktrace_push_msg("Failed to write channel id to message to send");
                goto clean_up;
            }

            if (!(result = send_cipher_message(channel_client, connection, channel_client->message_to_send))) {
                uk_utils_stacktrace_push_msg("Failed to send cipher message");
                goto clean_up;
            }
        }
    }
    else {
        if (!(result = process_message_request(channel_client, connection, data, data_size))) {
            uk_utils_stacktrace_push_msg("Failed to process message request");
            goto clean_up;
        }
    }

    result = true;

clean_up:
    uk_utils_safe_free(string_data);
    return result;
}

static void csl_read_consumer(void *parameter) {
    bool result;
    size_t received;
    int type;
    void *connection;
    uk_ue_channel_client *channel_client;

    result = true;
    channel_client = (uk_ue_channel_client *)parameter;
    connection = channel_client->connection;

    while (channel_client->running) {
        received = receive_cipher_message(channel_client, connection);
        result = true;

        // @todo set timeout in case of server lag or reboot
        if (received <= 0 || received == ULLONG_MAX) {
            uk_utils_logger_warn("Stopping client...");
            if (uk_utils_stacktrace_is_filled()) {
                uk_utils_logger_stacktrace("An error occured while receving a cipher message with the following stacktrace :");
                uk_utils_stacktrace_clean_up();
            }
            channel_client->running = false;
            result = false;
        }
        else {
            uk_utils_byte_stream_clean_up(channel_client->tmp_stream);
            if (!uk_utils_byte_writer_append_bytes(channel_client->tmp_stream, uk_utils_byte_stream_get_data(
                channel_client->received_message), uk_utils_byte_stream_get_size(channel_client->received_message))) {

                uk_utils_logger_error("Failed to write received message to working stream");
                continue;
            }
            uk_utils_byte_stream_set_position(channel_client->tmp_stream, 0);

            uk_utils_byte_read_next_int(channel_client->tmp_stream, &type);

            if (type == ALREADY_CONNECTED_RESPONSE) {
                uk_utils_logger_warn("Already connected");
                channel_client->running = false;
                result = false;
            }
            else if (type == NICKNAME_RESPONSE) {
                result = process_nickname_response(channel_client, channel_client->tmp_stream);
                uk_utils_logger_trace("Server has accepted this nickname.");
            }
            else if (type == CHANNEL_CONNECTION_RESPONSE) {
                uk_utils_logger_trace("CHANNEL_CONNECTION_RESPONSE");
                result = process_channel_connection_response(channel_client, channel_client->tmp_stream);
            }
            else if (type == MESSAGE && !channel_client->channel_key) {
                uk_utils_logger_warn("Cannot decipher received message for now, because we doesn't have to channel key");
            }
            else if (type == MESSAGE && channel_client->channel_key) {
                uk_utils_logger_trace("MESSAGE received");
                result = process_message_response(channel_client, channel_client->tmp_stream);
            }
            else if (type == CERTIFICATE_RESPONSE) {
                result = process_certificate_response(channel_client, channel_client->tmp_stream);
            }
            else if (type == CHANNEL_KEY_RESPONSE) {
                uk_utils_logger_trace("CHANNEL_KEY_RESPONSE");
                result = process_channel_key_response(channel_client, connection, channel_client->tmp_stream);
            }
            else if (type == CHANNEL_KEY_REQUEST && !channel_client->channel_key) {
                uk_utils_logger_warn("Receive a channel key request but we doesn't have it");
            }
            else if (type == CHANNEL_KEY_REQUEST && channel_client->channel_key) {
                uk_utils_logger_trace("CHANNEL_KEY_REQUEST");
                result = process_channel_key_request(channel_client, connection, channel_client->tmp_stream);
            }
            else if (channel_client->channel_id >= 0 && !channel_client->channel_key) {
                uk_utils_logger_warn("Cannot decrypt server data because we don't know channel key for now");
            } else {
                uk_utils_logger_warn("Received invalid data type from server '%d'.", type);
            }
        }

        if (!result) {
            if (uk_utils_stacktrace_is_filled()) {
                uk_utils_stacktrace_push_msg("Failed to process server response");
                uk_utils_logger_stacktrace("An error occured in this reading iteration with the following stacktrace :");
                uk_utils_stacktrace_clean_up();
            }
        }
    }
}

static void csl_write_consumer_stdin(void *parameter) {
    char *input;
    void *connection;
    uk_ue_channel_client *channel_client;
    unsigned char *bytes_input;

    input = NULL;
    bytes_input = NULL;
    channel_client = (uk_ue_channel_client *)parameter;
    connection = channel_client->connection;

    if (!send_nickname_request(channel_client, connection)) {
        uk_utils_stacktrace_push_msg("Failed to send nickname request");
        return;
    }

    while (channel_client->running) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_logger_stacktrace("An error occured in the last input iteration, with the following stacktrace :");
            uk_utils_stacktrace_clean_up();
        }

        uk_utils_safe_free(input);
        uk_utils_safe_free(bytes_input);

        if (channel_client->user_input_callback) {
            input = channel_client->user_input_callback(channel_client->user_context);
        } else {
            input = uk_utils_input_string(">");
        }

        if (!input) {
            continue;
        }

        if (!(bytes_input = uk_utils_bytes_create_from_string(input))) {
            uk_utils_stacktrace_push_msg("Failed to convert string input to bytes input");
            continue;
        }

        if (!process_user_input(channel_client, connection, bytes_input, strlen(input))) {
            uk_utils_stacktrace_push_msg("Failed to process user input");
        }
    }

    uk_utils_safe_free(input);
    uk_utils_safe_free(bytes_input);
}

static void csl_write_consumer_push(void *parameter) {
    void *connection;
    uk_ue_channel_client *channel_client;
    pushed_message *message;

    channel_client = (uk_ue_channel_client *)parameter;
    connection = channel_client->connection;

    if (!send_nickname_request(channel_client, connection)) {
        uk_utils_stacktrace_push_msg("Failed to send nickname request");
        return;
    }

    while (channel_client->running) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_logger_stacktrace("An error occured in the last input iteration, with the following stacktrace :");
            uk_utils_stacktrace_clean_up();
        }

        message = uk_utils_queuk_ue_front_wait(channel_client->push_mode_queue);

        if (!process_user_input(channel_client, connection, message->data, message->size)) {
            uk_utils_stacktrace_push_msg("Failed to process user input");
        }
    }
}

static bool process_get_certificate_request(uk_ue_channel_client *channel_client, uk_crypto_pkcs12_keystore *keystore,
    void *connection, const unsigned char *friendly_name, size_t friendly_name_size) {
    bool result;
    uk_utils_byte_stream *request, *response;
    unsigned char *certificate_data;
    int type, certificate_data_size;

    uk_utils_check_parameter_or_return(keystore);
    uk_utils_check_parameter_or_return(connection);
    uk_utils_check_parameter_or_return(friendly_name);
    uk_utils_check_parameter_or_return(friendly_name_size > 0);

    result = false;
    request = uk_utils_byte_stream_create();
    response = uk_utils_byte_stream_create();
    certificate_data = NULL;

    if (!uk_utils_byte_writer_append_int(request, channel_client->channel_id)) {
        uk_utils_stacktrace_push_msg("Failed to write channel id to request");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(request, GET_CERTIFICATE_REQUEST)) {
        uk_utils_stacktrace_push_msg("Failed to write GET_CERTIFICATE_REQUEST type to request");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(request, (int)friendly_name_size)) {
        uk_utils_stacktrace_push_msg("Failed to write friendly name size to request");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(request, (unsigned char *)friendly_name, friendly_name_size)) {
        uk_utils_stacktrace_push_msg("Failed to write friendly name to request");
        goto clean_up;
    }

    if (!send_cipher_message(channel_client, connection, request)) {
        uk_utils_stacktrace_push_msg("Failed to send GET_CERTIFICATE request to server");
        goto clean_up;
    }

    if (receive_cipher_message(channel_client, connection) <= 0) {
        uk_utils_stacktrace_push_msg("Failed to receive cipher message response of GET_CERTIFICATE request");
        goto clean_up;
    }

    if (!uk_utils_byte_writer_append_bytes(response, uk_utils_byte_stream_get_data(channel_client->received_message),
        uk_utils_byte_stream_get_size(channel_client->received_message))) {

        uk_utils_stacktrace_push_msg("Failed to write received message to response");
        goto clean_up;
    }
    uk_utils_byte_stream_set_position(response, 0);
    if (!uk_utils_byte_read_next_int(response, &type)) {
        uk_utils_stacktrace_push_msg("Failed to read request type in response");
        goto clean_up;
    }
    if (type != CERTIFICATE_RESPONSE) {
        uk_utils_logger_error("GET_CERTIFICATE request received an invalid response type");
        goto clean_up;
    }

    if (!uk_utils_byte_read_next_int(response, &certificate_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to read certificate data size in response");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_bytes(response, &certificate_data, (size_t)certificate_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to read certificate data in response");
        goto clean_up;
    }

    uk_utils_logger_info("Missing certificate received. Trying to add it to the cipher keystore...");
    if (!(uk_crypto_pkcs12_keystore_add_certificate_from_bytes(keystore, certificate_data, (size_t)certificate_data_size,
        (const unsigned char *)friendly_name, friendly_name_size))) {

        uk_utils_stacktrace_push_msg("Failed to add received certificate to cipher keystore");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_utils_byte_stream_destroy(request);
    uk_utils_byte_stream_destroy(response);
    uk_utils_safe_free(certificate_data);
    return result;
}

static bool process_channel_key_request(uk_ue_channel_client *channel_client, void *connection,
    uk_utils_byte_stream *request) {
    bool result;
    unsigned char *cipher_data, *friendly_name, *nickname;
    size_t cipher_data_size, friendly_name_size;
    uk_crypto_x509_certificate *client_certificate;
    uk_crypto_public_key *client_public_key;
    uk_utils_byte_stream *channel_key_stream;
    int nickname_size;

    uk_utils_check_parameter_or_return(connection);
    uk_utils_check_parameter_or_return(request);

    result = false;
    client_certificate = NULL;
    cipher_data = NULL;
    friendly_name = NULL;
    client_public_key = NULL;
    nickname = NULL;
    channel_key_stream = uk_utils_byte_stream_create();

    if (!uk_utils_byte_read_next_int(request, &nickname_size)) {
        uk_utils_stacktrace_push_msg("Failed to read nickname size in request");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_bytes(request, &nickname, (size_t)nickname_size)) {
        uk_utils_stacktrace_push_msg("Failed to read nickname in request");
        goto clean_up;
    }

    if (!(friendly_name = uk_crypto_friendly_name_build(nickname, (size_t)nickname_size, "CIPHER", &friendly_name_size))) {
        uk_utils_stacktrace_push_msg("Failed to build friendly name for CIPHER keystore");
        goto clean_up;
    }

    if (!(client_certificate = uk_crypto_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->cipher_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
        uk_utils_logger_warn("Cipher certificate of client was not found. Requesting the server...");

        if (!process_get_certificate_request(channel_client, channel_client->cipher_keystore, connection, (const unsigned char *)friendly_name, friendly_name_size)) {
            uk_utils_stacktrace_push_msg("Failed to get missing certificate");
            goto clean_up;
        }

        if (!uk_crypto_pkcs12_keystore_write(channel_client->cipher_keystore, channel_client->cipher_keystore_path, channel_client->keystore_password)) {
            uk_utils_stacktrace_push_msg("Failed to write keystore to '%s'", channel_client->cipher_keystore_path);
            goto clean_up;
        }

        uk_utils_logger_info("Retrying find cipher certificate...");

        if (!(client_certificate = uk_crypto_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->cipher_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
            uk_utils_stacktrace_push_msg("Failed to retreive client cipher certificate, while it should not happen");
            goto clean_up;
        }
    }

    if (!(client_public_key = uk_crypto_rsa_public_key_from_x509_certificate(client_certificate))) {
        uk_utils_stacktrace_push_msg("Failed to extract public key of client cipher certificate");
        goto clean_up;
    }

    if (!uk_utils_byte_writer_append_int(channel_key_stream, (int)channel_client->channel_key->size)) {
        uk_utils_stacktrace_push_msg("Failed to write channel key size to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(channel_key_stream, (int)channel_client->channel_iv_size)) {
        uk_utils_stacktrace_push_msg("Failed to write channel IV size to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(channel_key_stream, channel_client->channel_key->data, channel_client->channel_key->size)) {
        uk_utils_stacktrace_push_msg("Failed to write channel key to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(channel_key_stream, channel_client->channel_iv, channel_client->channel_iv_size)) {
        uk_utils_stacktrace_push_msg("Failed to write channel IV to stream");
        goto clean_up;
    }

    if (!uk_crypto_cipher_plain_data(uk_utils_byte_stream_get_data(channel_key_stream), uk_utils_byte_stream_get_size(channel_key_stream),
           client_public_key, channel_client->signer_keystore->private_key, &cipher_data, &cipher_data_size, channel_client->cipher_name,
              channel_client->digest_name)) {

        uk_utils_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

    // Build message to send : CHANNEL_KEY_REQUEST_ANSWER|<receiver_nickname>|<ciphered channel key>|
    uk_utils_byte_stream_clean_up(channel_key_stream);
    if (!uk_utils_byte_writer_append_int(channel_key_stream, channel_client->channel_id)) {
        uk_utils_stacktrace_push_msg("Failed to write channel id to response");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(channel_key_stream, CHANNEL_KEY_REQUEST_ANSWER)) {
        uk_utils_stacktrace_push_msg("Failed to write CHANNEL_KEY_REQUEST_ANSWER to response");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(channel_key_stream, nickname_size)) {
        uk_utils_stacktrace_push_msg("Failed to write nickname size to response");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(channel_key_stream, nickname, (size_t)nickname_size)) {
        uk_utils_stacktrace_push_msg("Failed to write nickname to response");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(channel_key_stream, (int)cipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to write cipher data size to response");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(channel_key_stream, cipher_data, cipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to write cipher data to response");
        goto clean_up;
    }

    if (!send_cipher_message(channel_client, connection, channel_key_stream)) {
        uk_utils_stacktrace_push_msg("Send the stream in a cipher message failed");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_utils_safe_free(cipher_data);
    uk_utils_safe_free(friendly_name);
    uk_crypto_public_key_destroy(client_public_key);
    uk_utils_byte_stream_destroy(channel_key_stream);
    uk_utils_safe_free(nickname);
    return result;
}

static bool send_nickname_request(uk_ue_channel_client *channel_client, void *connection) {
    uk_utils_check_parameter_or_return(connection);

    uk_utils_byte_stream_clean_up(channel_client->message_to_send);
    if (!uk_utils_byte_writer_append_int(channel_client->message_to_send, channel_client->channel_id)) {
        uk_utils_stacktrace_push_msg("Failed to write channel id to message to send");
        return false;
    }
    if (!uk_utils_byte_writer_append_int(channel_client->message_to_send, NICKNAME_REQUEST)) {
        uk_utils_stacktrace_push_msg("Failed to write NICKNAME_REQUEST type to message to send");
        return false;
    }
    if (!uk_utils_byte_writer_append_int(channel_client->message_to_send, (int)strlen(channel_client->nickname))) {
        uk_utils_stacktrace_push_msg("Failed to write nickname size to message to send");
        return false;
    }
    if (!uk_utils_byte_writer_append_bytes(channel_client->message_to_send, (unsigned char *)channel_client->nickname,
        strlen(channel_client->nickname))) {

        uk_utils_stacktrace_push_msg("Failed to write nickname to message to send");
        return false;
    }

    if (!send_message(channel_client, connection, channel_client->message_to_send)) {
        uk_utils_stacktrace_push_msg("Failed to send nickname request");
        return false;
    }

    return true;
}

static bool process_message_request(uk_ue_channel_client *channel_client, void *connection,
    unsigned char *data, size_t data_size) {

    bool result;
    uk_crypto_sym_encrypter *encrypter;
    unsigned char *cipher_data, *bytes_input;
    size_t cipher_data_size;

    uk_utils_check_parameter_or_return(connection);
    uk_utils_check_parameter_or_return(data);
    uk_utils_check_parameter_or_return(data_size > 0);

    result = false;
    encrypter = NULL;
    cipher_data = NULL;
    bytes_input = NULL;

    if (channel_client->channel_id >= 0 && channel_client->channel_key) {
        uk_utils_byte_writer_append_int(channel_client->message_to_send, MESSAGE);
        uk_utils_byte_writer_append_int(channel_client->message_to_send, (int)strlen(channel_client->nickname));
        uk_utils_byte_writer_append_bytes(channel_client->message_to_send, (unsigned char *)channel_client->nickname, (int)strlen(channel_client->nickname));

        if (channel_client->channel_key) {
            if (!(encrypter = uk_crypto_sym_encrypter_default_create(channel_client->channel_key))) {
                uk_utils_stacktrace_push_msg("Failed to create sym encrypter with this channel key");
                goto clean_up;
            }
            else if (!uk_crypto_sym_encrypter_encrypt(encrypter, data, data_size,
                channel_client->channel_iv, &cipher_data, &cipher_data_size)) {

                uk_utils_stacktrace_push_msg("Failed to encrypt this input");
                goto clean_up;
            }
            else if (!uk_utils_byte_writer_append_int(channel_client->message_to_send, (int)cipher_data_size)) {
                uk_utils_stacktrace_push_msg("Failed to append cipher data size");
                goto clean_up;
            }
            else if (!uk_utils_byte_writer_append_bytes(channel_client->message_to_send, cipher_data, cipher_data_size)) {
                uk_utils_stacktrace_push_msg("Failed to append cipher data to message to send");
                goto clean_up;
            }
        } else {
            uk_utils_byte_writer_append_bytes(channel_client->message_to_send, data, data_size);
        }

        result = send_cipher_message(channel_client, connection, channel_client->message_to_send);
    }
    else if (channel_client->channel_id < 0) {
        uk_utils_logger_warn("Cannot send message because no channel is selected");
    } else {
        uk_utils_logger_warn("Cannot send message because we don't know channel key for now");
    }

    result = true;

clean_up:
    uk_crypto_sym_encrypter_destroy(encrypter);
    uk_utils_safe_free(cipher_data);
    uk_utils_safe_free(bytes_input);
    return result;
}

static bool process_nickname_response(uk_ue_channel_client *channel_client, uk_utils_byte_stream *response) {
    bool result;
    int is_accepted;

    uk_utils_check_parameter_or_return(response);

    result = false;

    if (!uk_utils_byte_read_next_int(response, &is_accepted)) {
        uk_utils_stacktrace_push_msg("Failed to read is accepted field in response");
        goto clean_up;
    }

    if (is_accepted == 0) {
        uk_utils_logger_info("This nickname is already in use.");
        channel_client->running = false;
        goto clean_up;
    }
    else if (is_accepted != 1) {
        uk_utils_logger_warn("Response of nickname request is incomprehensible.");
        channel_client->running = false;
        goto clean_up;
    }

    result = true;

clean_up:
    return result;
}

static bool process_channel_connection_response(uk_ue_channel_client *channel_client, uk_utils_byte_stream *response) {
    bool result;
    int is_accepted, channel_key_state;

    result = false;

    uk_utils_check_parameter_or_return(response);

    if (!uk_utils_byte_read_next_int(response, &is_accepted)) {
        uk_utils_stacktrace_push_msg("Failed to read is accepted field in response");
        goto clean_up;
    }

    if (is_accepted == 0) {
        uk_utils_logger_info("This channel is already in use or cannot be use right now.");
        channel_client->running = false;
        goto clean_up;
    }
    else if (is_accepted != 1) {
        uk_utils_logger_warn("Response of channel connection request is incomprehensible.");
        goto clean_up;
    } else {
        if (!uk_utils_byte_read_next_int(response, &channel_client->channel_id)) {
            uk_utils_stacktrace_push_msg("Failed to read channel id in response");
            goto clean_up;
        }
        uk_utils_logger_trace("Channel connection has been accepted by the server with channel id %d.", channel_client->channel_id);

        if (!uk_utils_byte_read_next_int(response, &channel_key_state)) {
            uk_utils_stacktrace_push_msg("Failed to read channel key state in response");
            goto clean_up;
        }

        if (channel_key_state == CHANNEL_KEY_CREATOR_STATE) {
            uk_utils_logger_info("Generate random channel key");
            channel_client->channel_key = uk_crypto_sym_key_create_random();
            uk_utils_safe_alloc(channel_client->channel_iv, unsigned char, 16);
            if (!(uk_crypto_crypto_random_bytes(channel_client->channel_iv, 16))) {
                uk_utils_stacktrace_push_msg("Failed to get crypto random bytes for IV");
                goto clean_up;
            }
            channel_client->channel_iv_size = 16;
        }
        else if (channel_key_state == WAIT_CHANNEL_KEY_STATE) {
            uk_utils_logger_info("Waiting the channel key");
        }
        else {
            uk_utils_logger_warn("Unknown channel key action type. Default is waiting the channel key");
            goto clean_up;
        }
    }

    result = true;

clean_up:
    return result;
}

static bool process_message_response(uk_ue_channel_client *channel_client, uk_utils_byte_stream *message) {
    bool result;
    uk_crypto_sym_encrypter *decrypter;
    unsigned char *cipher_data, *decipher_data, *nickname;
    size_t decipher_data_size;
    int cipher_data_size, nickname_size;
    uk_utils_byte_stream *printer;

    uk_utils_check_parameter_or_return(message);

    result = false;
    decrypter = NULL;
    cipher_data = NULL;
    decipher_data = NULL;
    nickname = NULL;
    printer = uk_utils_byte_stream_create();

    if (!uk_utils_byte_read_next_int(message, &nickname_size)) {
        uk_utils_stacktrace_push_msg("Failed to read nickname size in message");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_bytes(message, &nickname, (size_t)nickname_size)) {
        uk_utils_stacktrace_push_msg("Failed to read nickname in message");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_int(message, &cipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to read cipher data size in message");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_bytes(message, &cipher_data, (size_t)cipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to read cipher data in message");
        goto clean_up;
    }

    if (!uk_utils_byte_writer_append_bytes(printer, nickname, (size_t)nickname_size)) {
        uk_utils_stacktrace_push_msg("Failed to write nickname to printer");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_string(printer, ": ")) {
        uk_utils_stacktrace_push_msg("Failed to write ':' delimiter to printer");
        goto clean_up;
    }

    if (!(decrypter = uk_crypto_sym_encrypter_default_create(channel_client->channel_key))) {
        uk_utils_stacktrace_push_msg("Failed to create default sym decrypter with channel_client channel key");
        goto clean_up;
    }
    if  (!uk_crypto_sym_encrypter_decrypt(decrypter, cipher_data, (size_t)cipher_data_size,
        channel_client->channel_iv, &decipher_data, &decipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to decrypt cipher data");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(printer, decipher_data, decipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to write decipher data to printer");
        goto clean_up;
    }

    if (!channel_client->write_callback(channel_client->user_context, printer)) {
        uk_utils_logger_warn("Failed to write the message with user write consumer");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_crypto_sym_encrypter_destroy(decrypter);
    uk_utils_safe_free(cipher_data);
    uk_utils_safe_free(decipher_data);
    uk_utils_safe_free(nickname);
    uk_utils_byte_stream_destroy(printer);
    return result;
}

static bool process_certificate_response(uk_ue_channel_client *channel_client, uk_utils_byte_stream *response) {
    bool result;
    uk_crypto_pkcs12_keystore *keystore;
    unsigned char *friendly_name, *certificate_data;
    int friendly_name_size, certificate_data_size;

    uk_utils_check_parameter_or_return(response);
    uk_utils_check_parameter_or_return(uk_utils_byte_stream_get_size(response));

    result = false;
    keystore = NULL;
    friendly_name = NULL;
    certificate_data = NULL;

    if (!uk_utils_byte_read_next_int(response, &friendly_name_size)) {
        uk_utils_stacktrace_push_msg("Failed to read friendly name size in response");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_bytes(response, &friendly_name, (size_t)friendly_name_size)) {
        uk_utils_stacktrace_push_msg("Failed to read friendly name in response");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_int(response, &certificate_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to read certificate data size in response");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_bytes(response, &certificate_data, (size_t)certificate_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to read certificate data in response");
        goto clean_up;
    }

    if (uk_utils_bytes_contains(friendly_name, friendly_name_size, (unsigned char *)"_CIPHER", strlen("_CIPHER"))) {
        keystore = channel_client->cipher_keystore;
    } else if (uk_utils_bytes_contains(friendly_name, friendly_name_size, (unsigned char *)"_SIGNER", strlen("_SIGNER"))) {
        keystore = channel_client->signer_keystore;
    } else {
        uk_utils_logger_warn("Invalid friendly name in GET_CERTIFICATE request");
        goto clean_up;
    }

    if (!uk_crypto_pkcs12_keystore_add_certificate_from_bytes(keystore, certificate_data, certificate_data_size, friendly_name, friendly_name_size)) {
        uk_utils_stacktrace_push_msg("Failed to add new certificate from bytes");
        goto clean_up;
    }

    result = true;

clean_up:
    return result;
}

static bool process_channel_key_response(uk_ue_channel_client *channel_client, void *connection,
    uk_utils_byte_stream *response) {
    bool result;
    uk_crypto_x509_certificate *key_owner_certificate;
    unsigned char *friendly_name, *plain_data, *key, *nickname, *cipher_data;
    uk_crypto_public_key *key_owner_public_key;
    uk_utils_byte_stream *channel_key_stream;
    int key_size, nickname_size, cipher_data_size, read_int;
    size_t friendly_name_size, plain_data_size;

    uk_utils_check_parameter_or_return(connection);
    uk_utils_check_parameter_or_return(response);
    uk_utils_check_parameter_or_return(uk_utils_byte_stream_get_size(response) > 0);

    result = false;
    key_owner_certificate = NULL;
    friendly_name = NULL;
    plain_data = NULL;
    key = NULL;
    nickname = NULL;
    cipher_data = NULL;
    key_owner_public_key = NULL;
    channel_key_stream = uk_utils_byte_stream_create();

    if (!uk_utils_byte_read_next_int(response, &nickname_size)) {
        uk_utils_stacktrace_push_msg("Failed to read nickname size in response");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_bytes(response, &nickname, (size_t)nickname_size)) {
        uk_utils_stacktrace_push_msg("Failed to read nickname in response");
        goto clean_up;
    }

    if (!(friendly_name = uk_crypto_friendly_name_build(nickname, (size_t)nickname_size, "SIGNER", &friendly_name_size))) {
        uk_utils_stacktrace_push_msg("Failed to build friendly name for SIGNER keystore");
        goto clean_up;
    }

    if (!(key_owner_certificate = uk_crypto_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->signer_keystore,
        (const unsigned char *)friendly_name, friendly_name_size))) {

        uk_utils_logger_warn("Signer certificate of client was not found. Requesting the server...");

        if (!process_get_certificate_request(channel_client, channel_client->signer_keystore, connection, (const unsigned char *)friendly_name, friendly_name_size)) {
            uk_utils_stacktrace_push_msg("Failed to get missing certificate");
            goto clean_up;
        }

        if (!uk_crypto_pkcs12_keystore_write(channel_client->signer_keystore, channel_client->signer_keystore_path, channel_client->keystore_password)) {
            uk_utils_stacktrace_push_msg("Failed to write keystore to '%s'", channel_client->signer_keystore_path);
            goto clean_up;
        }

        uk_utils_logger_info("Retrying find signer certificate...");

        if (!(key_owner_certificate = uk_crypto_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->signer_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
            uk_utils_stacktrace_push_msg("Failed to retreive client signer certificate, while it should not happen");
            goto clean_up;
        }
    }

    if (!(key_owner_public_key = uk_crypto_rsa_public_key_from_x509_certificate(key_owner_certificate))) {
        uk_utils_stacktrace_push_msg("Failed to get client public key from client certificate");
        goto clean_up;
    }

    if (!uk_utils_byte_read_next_int(response, &cipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to read cipher data size in response");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_bytes(response, &cipher_data, cipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to read cipher data in response");
        goto clean_up;
    }

    if (!uk_crypto_decipher_cipher_data(cipher_data, cipher_data_size, channel_client->cipher_keystore->private_key,
        key_owner_public_key, &plain_data, &plain_data_size, channel_client->cipher_name, channel_client->digest_name)) {

        uk_utils_stacktrace_push_msg("Failed decipher message data");
        goto clean_up;
    }

    if (!uk_utils_byte_writer_append_bytes(channel_key_stream, plain_data, plain_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to append plain data into channel key stream");
        goto clean_up;
    }
    uk_utils_byte_stream_set_position(channel_key_stream, 0);

    if (!uk_utils_byte_read_next_int(channel_key_stream, &read_int)) {
        uk_utils_stacktrace_push_msg("Failed to read channel key size");
        goto clean_up;
    }
    key_size = (size_t)read_int;

    if (!uk_utils_byte_read_next_int(channel_key_stream, &read_int)) {
        uk_utils_stacktrace_push_msg("Failed to read channel iv size");
        goto clean_up;
    }
    channel_client->channel_iv_size = (size_t)read_int;

    if (!uk_utils_byte_read_next_bytes(channel_key_stream, &key, key_size)) {
        uk_utils_stacktrace_push_msg("Failed to read channel key bytes");
        goto clean_up;
    }

    if (!uk_utils_byte_read_next_bytes(channel_key_stream, &channel_client->channel_iv, channel_client->channel_iv_size)) {
        uk_utils_stacktrace_push_msg("Failed to read channel iv bytes");
        goto clean_up;
    }

    if (!(channel_client->channel_key = uk_crypto_sym_key_create(key, key_size))) {
        uk_utils_stacktrace_push_msg("Failed to create sym key based on parsed deciphered data");
        goto clean_up;
    }

    uk_utils_logger_info("Channel key successfully received.");

    result = true;

clean_up:
    uk_crypto_public_key_destroy(key_owner_public_key);
    uk_utils_safe_free(friendly_name);
    uk_utils_safe_free(plain_data);
    uk_utils_safe_free(key);
    uk_utils_safe_free(nickname);
    uk_utils_safe_free(cipher_data);
    uk_utils_byte_stream_destroy(channel_key_stream);
    return result;
}

static bool generate_certificate(uk_crypto_x509_certificate **certificate, uk_crypto_private_key **private_key) {
    bool result;
    uk_crypto_x509_certificate_parameters *parameters;

    result = false;
    parameters = NULL;

    if (!(parameters = uk_crypto_x509_certificate_parameters_create())) {
        uk_utils_stacktrace_push_msg("Failed to create x509 parameters structure");
        return false;
    }

    if (!uk_crypto_x509_certificate_parameters_set_country(parameters, "FR")) {
        uk_utils_stacktrace_push_msg("Failed to set C to x509 parameters");
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_parameters_set_common_name(parameters, "CLIENT")) {
        uk_utils_stacktrace_push_msg("Failed to set CN to x509 parameters");
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_parameters_set_ca_type(parameters)) {
        uk_utils_stacktrace_push_msg("Failed to set certificate as ca type");
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_parameters_set_subject_key_identifier_as_hash(parameters)) {
        uk_utils_stacktrace_push_msg("Failed to set certificate subject key identifier as hash");
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_parameters_set_self_signed(parameters)) {
        uk_utils_stacktrace_push_msg("Failed to set certificate as self signed");
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_generate(parameters, certificate, private_key)) {
        uk_utils_stacktrace_push_msg("Failed to generate certificate and relative private key");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_crypto_x509_certificate_parameters_destroy(parameters);
    return result;
}
