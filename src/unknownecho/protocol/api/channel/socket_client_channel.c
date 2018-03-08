#include <unknownecho/protocol/api/channel/socket_client_channel.h>
#include <unknownecho/protocol/api/channel/socket_channel_message_type.h>
#include <unknownecho/protocol/api/channel/socket_client_channel_struct.h>

#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/bool.h>
#include <unknownecho/alloc.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/socket/socket_client.h>
#include <unknownecho/network/api/tls/tls_session.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/key/asym_key.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_sign.h>
#include <unknownecho/crypto/api/certificate/x509_csr.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_parameters.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_generation.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/api/csr/csr_request.h>
#include <unknownecho/crypto/factory/pkcs12_keystore_factory.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/crypto/utils/friendly_name.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_split.h>
#include <unknownecho/container/byte_vector.h>
#include <unknownecho/fileSystem/file_utility.h>
#include <unknownecho/fileSystem/folder_utility.h>
#include <unknownecho/input.h>

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>


static ue_socket_client_channel **client_channels = NULL;
static int max_client_channels_number = 10;


#if defined(WIN32)
	#include <windows.h>
#elif defined(__UNIX__)
	#include <unistd.h>
#endif


#define CSR_SERVER_CERTIFICATE_PATH    "/certificate/csr_server.pem"
#define TLS_SERVER_CERTIFICATE_PATH    "/certificate/tls_server.pem"
#define CIPHER_SERVER_CERTIFICATE_PATH "/certificate/cipher_server.pem"
#define SIGNER_SERVER_CERTIFICATE_PATH "/certificate/signer_server.pem"
#define TLS_KEYSTORE_PATH              "/keystore/tls_client_keystore.p12"
#define CIPHER_KEYSTORE_PATH    	    "/keystore/cipher_client_keystore.p12"
#define SIGNER_KEYSTORE_PATH           "/keystore/signer_client_keystore.p12"
#define LOGGER_FILE_NAME               "logs.txt"


static void handle_signal(int sig, void (*h)(int), int options);

static void shutdown_client(int sig);

static bool send_message(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection, ue_byte_stream *message_to_send);

static size_t receive_message(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection);

static bool send_cipher_message(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection, ue_byte_stream *message_to_send);

static size_t receive_cipher_message(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection);

static bool create_keystores(ue_socket_client_channel *client_channel, const char *csr_server_host, unsigned short int csr_server_port, char *keystore_password);

static bool send_csr(ue_socket_client_channel *client_channel, csr_context *context, int csr_sub_type);

static bool csr_read_consumer(void *parameter);

static bool tls_read_consumer(void *parameter);

static bool tls_write_consumer(void *parameter);

static bool process_get_certificate_request(ue_socket_client_channel *client_channel, ue_pkcs12_keystore *keystore,
	ue_socket_client_connection *connection, const unsigned char *friendly_name, size_t friendly_name_size);

static bool process_channel_key_request(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection,
	ue_byte_stream *request);

static bool send_nickname_request(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection);

static bool process_message_request(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection, char *input);

static bool process_nickname_response(ue_socket_client_channel *client_channel, ue_byte_stream *response);

static bool process_channel_connection_response(ue_socket_client_channel *client_channel, ue_byte_stream *response);

static bool process_message_response(ue_socket_client_channel *client_channel, ue_byte_stream *message);

static bool process_certificate_response(ue_socket_client_channel *client_channel, ue_byte_stream *response);

static bool process_channel_key_response(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection,
	ue_byte_stream *response);

static bool generate_certificate(ue_x509_certificate **certificate, ue_private_key **private_key);


bool ue_socket_client_channel_init() {
	int i;

	ue_safe_alloc(client_channels, ue_socket_client_channel *, max_client_channels_number);
	for (i = 0; i < max_client_channels_number; i++) {
		client_channels[i] = NULL;
	}

	return true;
}

void ue_socket_client_channel_uninit() {
	ue_safe_free(client_channels);
}

static int get_available_client_channel_index() {
	int i;

	for (i = 0; i < max_client_channels_number; i++) {
		if (!client_channels[i]) {
			return i;
		}
	}

	return -1;
}

ue_socket_client_channel *ue_socket_client_channel_create(char *root_path, char *nickname, const char *csr_server_host, int csr_server_port,
	const char *tls_server_host, int tls_server_port, char *keystore_password, bool (*write_consumer)(ue_byte_stream *printer)) {

	ue_socket_client_channel *client_channel;
	bool result;
	char *certificate_folder_path, *keystore_folder_path, *logs_file_name;
	result = false;
	certificate_folder_path = NULL;
	keystore_folder_path = NULL;
	logs_file_name = NULL;
	int available_client_channel_index;

	available_client_channel_index = get_available_client_channel_index();

	ue_safe_alloc(client_channels[available_client_channel_index], ue_socket_client_channel, 1);
	client_channel = client_channels[available_client_channel_index];
    client_channel->fd = -1;
    client_channel->connection = NULL;
    client_channel->new_message = NULL;
    client_channel->running = false;
    client_channel->nickname = NULL;
    client_channel->read_thread = NULL;
    client_channel->write_thread = NULL;
    client_channel->tls_session = NULL;
	client_channel->channel_id = -1;
	client_channel->keystore_password = NULL;
	client_channel->tls_keystore_ok = false;
	client_channel->cipher_keystore_ok = false;
	client_channel->signer_keystore_ok = false;
	client_channel->tls_csr_context = NULL;
	client_channel->cipher_csr_context = NULL;
	client_channel->signer_csr_context = NULL;
	client_channel->tls_keystore = NULL;
	client_channel->cipher_keystore = NULL;
    client_channel->signer_keystore = NULL;
	client_channel->channel_key = NULL;
	client_channel->channel_iv = NULL;
	client_channel->channel_iv_size = 0;
	client_channel->root_path = NULL;
	client_channel->tls_server_host = NULL;
	client_channel->write_consumer = write_consumer;

	if (!(client_channel->mutex = ue_thread_mutex_create())) {
		ue_stacktrace_push_msg("Failed to init client_channel->mutex");
		goto clean_up;
	}

	if (!(client_channel->cond = ue_thread_cond_create())) {
		ue_stacktrace_push_msg("Failed to init client_channel->cond");
		goto clean_up;
	}

	client_channel->nickname = ue_string_create_from(nickname);
	client_channel->root_path = ue_string_create_from(root_path);
	client_channel->tls_server_host = ue_string_create_from(tls_server_host);
	client_channel->tls_server_port = tls_server_port;

	logs_file_name = ue_strcat_variadic("sssss", client_channel->root_path, "/", client_channel->nickname, "/", LOGGER_FILE_NAME);
	client_channel->logs_file = NULL;
    if (!(client_channel->logs_file = fopen(logs_file_name, "a"))) {
        ue_stacktrace_push_msg("Failed to open logs file at path '%s'", logs_file_name)
    }

	ue_logger_set_fp(ue_logger_manager_get_logger(), client_channel->logs_file);

    ue_logger_set_details(ue_logger_manager_get_logger(), true);

	client_channel->csr_server_certificate_path = ue_strcat_variadic("ssss", client_channel->root_path, "/", client_channel->nickname, CSR_SERVER_CERTIFICATE_PATH);
	client_channel->tls_server_certificate_path = ue_strcat_variadic("ssss", client_channel->root_path, "/", client_channel->nickname, TLS_SERVER_CERTIFICATE_PATH);
	client_channel->cipher_server_certificate_path = ue_strcat_variadic("ssss", client_channel->root_path, "/", client_channel->nickname, CIPHER_SERVER_CERTIFICATE_PATH);
	client_channel->signer_server_certificate_path = ue_strcat_variadic("ssss", client_channel->root_path, "/", client_channel->nickname, SIGNER_SERVER_CERTIFICATE_PATH);
	client_channel->tls_keystore_path = ue_strcat_variadic("ssss", client_channel->root_path, "/", client_channel->nickname, TLS_KEYSTORE_PATH);
	client_channel->cipher_keystore_path = ue_strcat_variadic("ssss", client_channel->root_path, "/", client_channel->nickname, CIPHER_KEYSTORE_PATH);
	client_channel->signer_keystore_path = ue_strcat_variadic("ssss", client_channel->root_path, "/", client_channel->nickname, SIGNER_KEYSTORE_PATH);

	client_channel->keystore_password = ue_string_create_from(keystore_password);

	certificate_folder_path = ue_strcat_variadic("ssss", client_channel->root_path, "/", client_channel->nickname, "/certificate");
	keystore_folder_path = ue_strcat_variadic("ssss", client_channel->root_path, "/", client_channel->nickname, "/keystore");

	if (!ue_is_dir_exists(certificate_folder_path)) {
		ue_logger_info("Creating '%s'...", certificate_folder_path);
		if (!ue_create_folder(certificate_folder_path)) {
			ue_stacktrace_push_msg("Failed to create '%s'", certificate_folder_path);
			goto clean_up;
		}
	}

	if (!ue_is_dir_exists(keystore_folder_path)) {
		ue_logger_info("Creating '%s'...", keystore_folder_path);
		if (!ue_create_folder(keystore_folder_path)) {
			ue_stacktrace_push_msg("Failed to create '%s'", keystore_folder_path);
			goto clean_up;
		}
	}

	if (!ue_x509_certificate_load_from_file(client_channel->csr_server_certificate_path, &client_channel->csr_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load CSR server certificate from path '%s'", client_channel->csr_server_certificate_path);
		ue_safe_free(client_channel);
		goto clean_up;
	}

	if (!ue_x509_certificate_load_from_file(client_channel->tls_server_certificate_path, &client_channel->tls_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load TLS server certificate from path '%s'", client_channel->tls_server_certificate_path);
		ue_safe_free(client_channel);
		goto clean_up;
	}

	if (!ue_x509_certificate_load_from_file(client_channel->cipher_server_certificate_path, &client_channel->cipher_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load cipher server certificate from path '%s'", client_channel->cipher_server_certificate_path);
		ue_safe_free(client_channel);
		goto clean_up;
	}

	if (!ue_x509_certificate_load_from_file(client_channel->signer_server_certificate_path, &client_channel->signer_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load signer server certificate from path '%s'", client_channel->signer_server_certificate_path);
		ue_safe_free(client_channel);
		goto clean_up;
	}

	if (!create_keystores(client_channel, csr_server_host, csr_server_port, client_channel->keystore_password)) {
		ue_stacktrace_push_msg("Failed to create keystore");
		ue_socket_client_channel_destroy(client_channel);
		goto clean_up;
	}

	result = true;

clean_up:
	ue_safe_free(certificate_folder_path);
	ue_safe_free(keystore_folder_path);
	ue_safe_free(logs_file_name);
	if (!result) {
		ue_socket_client_channel_destroy(client_channel);
		client_channel = NULL;
	}
	return client_channel;
}

void ue_socket_client_channel_destroy(ue_socket_client_channel *client_channel) {
	if (!client_channel) {
		return;
	}
	ue_safe_free(client_channel->read_thread)
	ue_safe_free(client_channel->write_thread)
	ue_thread_mutex_destroy(client_channel->mutex);
	ue_thread_cond_destroy(client_channel->cond);
	if (client_channel->tls_session) {
		ue_tls_session_destroy(client_channel->tls_session);
	}
	ue_byte_stream_destroy(client_channel->new_message);
	ue_safe_str_free(client_channel->nickname)
	ue_safe_str_free(client_channel->keystore_password);
	if (client_channel->connection) {
		ue_socket_client_connection_destroy(client_channel->connection);
	}
	else {
		ue_socket_close(client_channel->fd);
	}
	ue_x509_certificate_destroy(client_channel->csr_server_certificate);
	ue_x509_certificate_destroy(client_channel->tls_server_certificate);
	ue_x509_certificate_destroy(client_channel->cipher_server_certificate);
	ue_x509_certificate_destroy(client_channel->signer_server_certificate);
	if (client_channel->tls_csr_context) {
		ue_sym_key_destroy(client_channel->tls_csr_context->future_key);
		ue_safe_free(client_channel->tls_csr_context->iv);
		ue_safe_free(client_channel->tls_csr_context);
	}
	if (client_channel->cipher_csr_context) {
		ue_sym_key_destroy(client_channel->cipher_csr_context->future_key);
		ue_safe_free(client_channel->cipher_csr_context->iv);
		ue_safe_free(client_channel->cipher_csr_context);
	}
	if (client_channel->signer_csr_context) {
		ue_sym_key_destroy(client_channel->signer_csr_context->future_key);
		ue_safe_free(client_channel->signer_csr_context->iv);
		ue_safe_free(client_channel->signer_csr_context);
	}
	ue_pkcs12_keystore_destroy(client_channel->tls_keystore);
	ue_pkcs12_keystore_destroy(client_channel->cipher_keystore);
	ue_pkcs12_keystore_destroy(client_channel->signer_keystore);
	ue_safe_free(client_channel->csr_server_certificate_path);
	ue_safe_free(client_channel->tls_server_certificate_path);
	ue_safe_free(client_channel->cipher_server_certificate_path);
	ue_safe_free(client_channel->signer_server_certificate_path);
	ue_safe_free(client_channel->tls_keystore_path);
	ue_safe_free(client_channel->cipher_keystore_path);
	ue_safe_free(client_channel->signer_keystore_path);
	ue_sym_key_destroy(client_channel->channel_key);
	ue_safe_free(client_channel->channel_iv);
	ue_safe_fclose(client_channel->logs_file);
	ue_safe_free(client_channel->root_path);
	ue_safe_free(client_channel->tls_server_host);
	ue_safe_free(client_channel);
}

bool ue_socket_client_channel_start(ue_socket_client_channel *client_channel) {

	ue_check_parameter_or_return(client_channel->tls_server_host);
	ue_check_parameter_or_return(client_channel->tls_server_port > 0);

    handle_signal(SIGINT, shutdown_client, 0);
    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

    ue_x509_certificate **ca_certificates = NULL;
    ue_safe_alloc(ca_certificates, ue_x509_certificate *, 1);
    ca_certificates[0] = client_channel->tls_server_certificate;

	/* @todo pass keystore ptr instead of path */
	if (!(client_channel->tls_session = ue_tls_session_create_client((char *)client_channel->tls_keystore_path, client_channel->keystore_password, ca_certificates, 1))) {
		ue_stacktrace_push_msg("Failed to create TLS session");
		return false;
	}

	ue_safe_free(ca_certificates);

    client_channel->fd = ue_socket_open_tcp();
    if (!(client_channel->connection = ue_socket_connect(client_channel->fd, AF_INET, client_channel->tls_server_host, client_channel->tls_server_port, client_channel->tls_session))) {
        ue_stacktrace_push_msg("Failed to connect socket to server");
        return false;
    }

	client_channel->running = true;
	client_channel->transmission_state = WRITING_STATE;
	client_channel->new_message = ue_byte_stream_create();
	client_channel->channel_id = -1;
	client_channel->connection->optional_data = client_channel;

    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
		client_channel->read_thread = ue_thread_create((void *)tls_read_consumer, (void *)client_channel->connection);
		client_channel->write_thread = ue_thread_create((void *)tls_write_consumer, (void *)client_channel->connection);
    _Pragma("GCC diagnostic pop")

    ue_thread_join(client_channel->read_thread, NULL);
    ue_thread_join(client_channel->write_thread, NULL);

    return true;
}

static void handle_signal(int sig, void (*h)(int), int options) {
    struct sigaction s;

    s.sa_handler = h;
    sigemptyset(&s.sa_mask);
    s.sa_flags = options;
    if (sigaction(sig, &s, NULL) < 0) {
        ue_stacktrace_push_errno();
    }
}

static void shutdown_client(int sig) {
	int i;

    ue_logger_trace("Signal received %d", sig);

	for (i = 0; i < max_client_channels_number; i++) {
		if (!client_channels[i]) {
			continue;
		}
		ue_logger_info("Shuting down client #%d...", i);
		client_channels[i]->running = false;
		client_channels[i]->transmission_state = CLOSING_STATE;
		ue_thread_cond_signal(client_channels[i]->cond);
	}
}

static bool send_message(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection, ue_byte_stream *message_to_send) {
	size_t sent;

	ue_check_parameter_or_return(connection);
	ue_check_parameter_or_return(connection->fd > 0);
	ue_check_parameter_or_return(message_to_send);
	ue_check_parameter_or_return(ue_byte_stream_get_size(message_to_send) > 0);

	ue_thread_mutex_lock(client_channel->mutex);
	client_channel->transmission_state = WRITING_STATE;
	sent = ue_socket_send_data(connection->fd, ue_byte_stream_get_data(message_to_send), ue_byte_stream_get_size(message_to_send), connection->tls);
	client_channel->transmission_state = READING_STATE;
	ue_thread_cond_signal(client_channel->cond);
	ue_thread_mutex_unlock(client_channel->mutex);

	if (sent < 0 || sent == ULLONG_MAX) {
		ue_logger_info("Connection is interrupted.");
		ue_stacktrace_push_msg("Failed to send message to server");
		client_channel->running = false;
		return false;
	}

	return true;
}

static size_t receive_message(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection) {
	size_t received;

	ue_thread_mutex_lock(client_channel->mutex);
    while (client_channel->transmission_state == WRITING_STATE) {
        ue_thread_cond_wait(client_channel->cond, client_channel->mutex);
    }
    ue_thread_mutex_unlock(client_channel->mutex);
	ue_byte_stream_clean_up(connection->received_message);
    received = ue_socket_receive_bytes_sync(connection->fd, connection->received_message, false, connection->tls);

    return received;
}

static bool send_cipher_message(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection, ue_byte_stream *message_to_send) {
	bool result;
	unsigned char *cipher_data;
	size_t cipher_data_size;
	ue_x509_certificate *server_certificate;
    ue_public_key *server_public_key;

	result = false;
	cipher_data = NULL;
	server_public_key = NULL;

	if (!(server_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(client_channel->cipher_keystore, (const unsigned char *)"CIPHER_SERVER", strlen("CIPHER_SERVER")))) {
        ue_stacktrace_push_msg("Failed to get cipher client certificate");
        goto clean_up;
    }

    if (!(server_public_key = ue_rsa_public_key_from_x509_certificate(server_certificate))) {
        ue_stacktrace_push_msg("Failed to get server public key from server certificate");
        goto clean_up;
    }

	if (!ue_cipher_plain_data(ue_byte_stream_get_data(message_to_send), ue_byte_stream_get_size(message_to_send),
		server_public_key, client_channel->signer_keystore->private_key, &cipher_data, &cipher_data_size, "aes-256-cbc")) {

        ue_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

	ue_byte_stream_clean_up(message_to_send);

	if (!ue_byte_writer_append_bytes(message_to_send, cipher_data, cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write cipher data to message to send");
		goto clean_up;
	}

	if (!send_message(client_channel, connection, message_to_send)) {
		ue_stacktrace_push_msg("Failed to send cipher message");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_safe_free(cipher_data);
	ue_public_key_destroy(server_public_key);
	return result;
}

static size_t receive_cipher_message(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection) {
	unsigned char *plain_data;
    size_t received, plain_data_size;
	ue_x509_certificate *server_certificate;
	ue_public_key *server_public_key;

	plain_data = NULL;
	server_public_key = NULL;

	received = receive_message(client_channel, connection);
	if (received <= 0 || received == ULLONG_MAX) {
		ue_logger_warn("Connection with server is interrupted.");
		goto clean_up;
	}

	if (!(server_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(client_channel->signer_keystore, (const unsigned char *)"SIGNER_SERVER", strlen("SIGNER_SERVER")))) {
		ue_stacktrace_push_msg("Failed to find server signer certificate");
		received = -1;
		goto clean_up;
	}

	if (!(server_public_key = ue_rsa_public_key_from_x509_certificate(server_certificate))) {
        ue_stacktrace_push_msg("Failed to get server public key from server certificate");
		received = -1;
        goto clean_up;
    }

	if (!ue_decipher_cipher_data(ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message),
		client_channel->cipher_keystore->private_key, server_public_key, &plain_data, &plain_data_size, "aes-256-cbc")) {

		received = -1;
		ue_stacktrace_push_msg("Failed decipher message data");
		goto clean_up;
	}

	ue_byte_stream_clean_up(connection->received_message);

	if (!ue_byte_writer_append_bytes(connection->received_message, plain_data, plain_data_size)) {
		received = -1;
		ue_stacktrace_push_msg("Failed to write plain data to received message");
		goto clean_up;
	}

clean_up:
	ue_public_key_destroy(server_public_key);
	ue_safe_free(plain_data);
	return received;
}

static bool create_keystores(ue_socket_client_channel *client_channel, const char *csr_server_host, unsigned short int csr_server_port, char *keystore_password) {
	bool result;
	bool tls_keystore_exists, cipher_keystore_exists, signer_keystore_exists;

	ue_check_parameter_or_return(csr_server_host);
	ue_check_parameter_or_return(csr_server_port > 0);
	ue_check_parameter_or_return(keystore_password);

	result = false;

	tls_keystore_exists = ue_is_file_exists(client_channel->tls_keystore_path);
	cipher_keystore_exists = ue_is_file_exists(client_channel->cipher_keystore_path);
	signer_keystore_exists = ue_is_file_exists(client_channel->signer_keystore_path);

	if (!tls_keystore_exists) {
		ue_safe_alloc(client_channel->tls_csr_context, csr_context, 1);
		client_channel->tls_csr_context->signed_certificate = NULL;
		client_channel->tls_csr_context->private_key = NULL;
		client_channel->tls_csr_context->future_key = NULL;
		client_channel->tls_csr_context->iv = NULL;
	} else {
		if (!(client_channel->tls_keystore = ue_pkcs12_keystore_load(client_channel->tls_keystore_path, client_channel->keystore_password))) {
	        ue_stacktrace_push_msg("Failed to load cipher pkcs12 keystore");
	        goto clean_up;
	    }
	}

	if (!cipher_keystore_exists) {
		ue_safe_alloc(client_channel->cipher_csr_context, csr_context, 1);
		client_channel->cipher_csr_context->signed_certificate = NULL;
		client_channel->cipher_csr_context->private_key = NULL;
		client_channel->cipher_csr_context->future_key = NULL;
		client_channel->cipher_csr_context->iv = NULL;
	} else {
		if (!(client_channel->cipher_keystore = ue_pkcs12_keystore_load(client_channel->cipher_keystore_path, client_channel->keystore_password))) {
	        ue_stacktrace_push_msg("Failed to load cipher pkcs12 keystore");
	        goto clean_up;
	    }
	}

	if (!signer_keystore_exists) {
		ue_safe_alloc(client_channel->signer_csr_context, csr_context, 1);
		client_channel->signer_csr_context->signed_certificate = NULL;
		client_channel->signer_csr_context->private_key = NULL;
		client_channel->signer_csr_context->future_key = NULL;
		client_channel->signer_csr_context->iv = NULL;
	} else {
		if (!(client_channel->signer_keystore = ue_pkcs12_keystore_load(client_channel->signer_keystore_path, client_channel->keystore_password))) {
			ue_stacktrace_push_msg("Failed to load signer pkcs12 keystore");
			goto clean_up;
		}
	}

	if (!tls_keystore_exists || !cipher_keystore_exists || !signer_keystore_exists) {
		client_channel->fd = ue_socket_open_tcp();
		if (!(client_channel->connection = ue_socket_connect(client_channel->fd, AF_INET, csr_server_host, csr_server_port, NULL))) {
			ue_stacktrace_push_msg("Failed to connect socket to server");
			goto clean_up;
		}

		client_channel->running = true;
		client_channel->transmission_state = WRITING_STATE;
		client_channel->connection->optional_data = client_channel;

	    _Pragma("GCC diagnostic push")
	    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
			client_channel->read_thread = ue_thread_create((void *)csr_read_consumer, (void *)client_channel->connection);
	    _Pragma("GCC diagnostic pop")
	}

	if (!tls_keystore_exists) {
		ue_logger_info("TLS keystore doesn't exists. A CSR will be built.");
		if (!send_csr(client_channel, client_channel->tls_csr_context, CSR_TLS_REQUEST)) {
			ue_stacktrace_push_msg("Failed to process CSR exchange for TLS");
			goto clean_up;
		}
	} else {
		client_channel->tls_keystore_ok = true;
	}

	if (!cipher_keystore_exists) {
		ue_logger_info("Cipher keystore doesn't exists. A CSR will be built.");
		if (!send_csr(client_channel, client_channel->cipher_csr_context, CSR_CIPHER_REQUEST)) {
			ue_stacktrace_push_msg("Failed to process CSR exchange for cipher");
			goto clean_up;
		}
	} else {
		client_channel->cipher_keystore_ok = true;
	}

	if (!signer_keystore_exists) {
		ue_logger_info("Signer keystore doesn't exists. A CSR will be built.");
		if (!send_csr(client_channel, client_channel->signer_csr_context, CSR_SIGNER_REQUEST)) {
			ue_stacktrace_push_msg("Failed to process CSR exchange for signer");
			goto clean_up;
		}
	} else {
		client_channel->signer_keystore_ok = true;
	}

	if (!tls_keystore_exists || !cipher_keystore_exists || !signer_keystore_exists) {
		ue_thread_join(client_channel->read_thread, NULL);

		if (ue_stacktrace_is_filled()) {
			ue_logger_stacktrace("An error occurred while processing read_consumer()");
			ue_stacktrace_clean_up();
			goto clean_up;
		}
	}

	if (!tls_keystore_exists) {
		if (ue_x509_certificate_verify(client_channel->tls_csr_context->signed_certificate, client_channel->tls_server_certificate)) {
			ue_logger_info("Certificate is correctly signed by the CA");
		} else {
			ue_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
			goto clean_up;
		}

		if (!(client_channel->tls_keystore = ue_pkcs12_keystore_create(client_channel->tls_csr_context->signed_certificate, client_channel->tls_csr_context->private_key, "TLS_CLIENT"))) {
			ue_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
			goto clean_up;
		}

		ue_pkcs12_keystore_add_certificate_from_file(client_channel->tls_keystore, client_channel->tls_server_certificate_path, (const unsigned char *)"TLS_SERVER", strlen("TLS_SERVER"));

		if (!ue_pkcs12_keystore_write(client_channel->tls_keystore, client_channel->tls_keystore_path, keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", client_channel->tls_keystore_path);
			goto clean_up;
		}

		ue_logger_info("TLS keystore created.");
	}

	if (!cipher_keystore_exists) {
		if (ue_x509_certificate_verify(client_channel->cipher_csr_context->signed_certificate, client_channel->cipher_server_certificate)) {
			ue_logger_info("Certificate is correctly signed by the CA");
		} else {
			ue_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
			goto clean_up;
		}

		if (!(client_channel->cipher_keystore = ue_pkcs12_keystore_create(client_channel->cipher_csr_context->signed_certificate, client_channel->cipher_csr_context->private_key,
			"CIPHER_CLIENT"))) {

			ue_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
			goto clean_up;
		}

		ue_pkcs12_keystore_add_certificate_from_file(client_channel->cipher_keystore, client_channel->cipher_server_certificate_path, (const unsigned char *)"CIPHER_SERVER", strlen("CIPHER_SERVER"));

		if (!ue_pkcs12_keystore_write(client_channel->cipher_keystore, client_channel->cipher_keystore_path, keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", client_channel->cipher_keystore_path);
			goto clean_up;
		}

		ue_logger_info("Cipher keystore created.");
	}

	if (!signer_keystore_exists) {
		if (ue_x509_certificate_verify(client_channel->signer_csr_context->signed_certificate, client_channel->signer_server_certificate)) {
			ue_logger_info("Certificate is correctly signed by the CA");
		} else {
			ue_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
			goto clean_up;
		}

		if (!(client_channel->signer_keystore = ue_pkcs12_keystore_create(client_channel->signer_csr_context->signed_certificate, client_channel->signer_csr_context->private_key,
			"SIGNER_CLIENT"))) {

			ue_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
			goto clean_up;
		}

		ue_pkcs12_keystore_add_certificate_from_file(client_channel->signer_keystore, client_channel->signer_server_certificate_path, (const unsigned char *)"SIGNER_SERVER", strlen("SIGNER_SERVER"));

		if (!ue_pkcs12_keystore_write(client_channel->signer_keystore, client_channel->signer_keystore_path, keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", client_channel->signer_keystore_path);
			goto clean_up;
		}

		ue_logger_info("Signer keystore created.");
	}

	result = true;

clean_up:
	return result;
}

static bool send_csr(ue_socket_client_channel *client_channel, csr_context *context, int csr_sub_type) {
	bool result;
	ue_x509_certificate *certificate;
	size_t cipher_data_size;
	unsigned char *csr_request;
	ue_byte_stream *stream;
	ue_public_key *ca_public_key;

	ue_check_parameter_or_return(context);
	ue_check_parameter_or_return(csr_sub_type == CSR_TLS_REQUEST || csr_sub_type == CSR_CIPHER_REQUEST || csr_sub_type == CSR_SIGNER_REQUEST);

	result = false;
	certificate = NULL;
	csr_request = NULL;
	stream = ue_byte_stream_create();
	ca_public_key = NULL;

	if (!(context->future_key = ue_sym_key_create_random())) {
		ue_stacktrace_push_msg("Failed to gen random sym key for server response encryption");
		goto clean_up;
	}

	ue_safe_alloc(context->iv, unsigned char, 16);
	if (!(ue_crypto_random_bytes(context->iv, 16))) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for IV");
		goto clean_up;
	}
	context->iv_size = 16;

	if (!(ca_public_key = ue_rsa_public_key_from_x509_certificate(client_channel->csr_server_certificate))) {
		ue_stacktrace_push_msg("Failed to extract RSA public key from CA certificate");
		goto clean_up;
	}

	if (!generate_certificate(&certificate, &context->private_key)) {
        ue_stacktrace_push_msg("Failed to generate x509 certificate and private key");
        goto clean_up;
    }

	if (!(csr_request = ue_csr_build_client_request(certificate, context->private_key, ca_public_key, &cipher_data_size, context->future_key, context->iv,
		context->iv_size))) {

		ue_stacktrace_push_msg("Failed to build CSR request");
		goto clean_up;
	}

	if (!ue_byte_writer_append_int(stream, csr_sub_type)) {
		ue_stacktrace_push_msg("Failed to write CSR sub type to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(stream, (int)strlen(client_channel->nickname))) {
		ue_stacktrace_push_msg("Failed to write nickname size to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(stream, (unsigned char *)client_channel->nickname, strlen(client_channel->nickname))) {
		ue_stacktrace_push_msg("Failed to write nickname to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(stream, (int)cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write cipher data size to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(stream, csr_request, cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write CSR request to stream");
		goto clean_up;
	}

	ue_byte_stream_clean_up(client_channel->connection->message_to_send);
	if (!ue_byte_writer_append_bytes(client_channel->connection->message_to_send, ue_byte_stream_get_data(stream), ue_byte_stream_get_size(stream))) {
		ue_stacktrace_push_msg("Failed to write stream data to message to send");
		goto clean_up;
	}

	if (!send_message(client_channel, client_channel->connection, client_channel->connection->message_to_send)) {
		ue_stacktrace_push_msg("Failed to send message to send");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_safe_free(csr_request);
	ue_byte_stream_destroy(stream);
	ue_public_key_destroy(ca_public_key);
	ue_x509_certificate_destroy(certificate);
	return result;
}

static bool csr_read_consumer(void *parameter) {
	size_t received;
	bool result;
	ue_socket_client_connection *connection;
	ue_byte_stream *response;
	int csr_sub_type, csr_response_size;
	unsigned char *csr_response;
	ue_socket_client_channel *client_channel;

	result = true;
	connection = (ue_socket_client_connection *)parameter;
	response = ue_byte_stream_create();
	csr_response = NULL;
	client_channel = connection->optional_data;

	while (client_channel->running) {
		received = receive_message(client_channel, connection);
		result = true;

		// @todo set timeout in case of server lag or reboot
		if (received <= 0 || received == ULLONG_MAX) {
			ue_logger_warn("Connection with server is interrupted. Stopping client...");
			if (ue_stacktrace_is_filled()) {
				ue_stacktrace_push_msg("Failed to receive server message");
			}
			client_channel->running = false;
			result = false;
		}
		else {
			ue_byte_stream_clean_up(response);
			if (!ue_byte_writer_append_bytes(response, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message))) {
				ue_stacktrace_push_msg("Failed write received message to response");
				goto clean_up;
			}
			ue_byte_stream_set_position(response, 0);

			if (!ue_byte_read_next_int(response, &csr_sub_type)) {
				ue_stacktrace_push_msg("Failed to read CSR sub type in response");
				goto clean_up;
			}

			if (csr_sub_type != CSR_TLS_RESPONSE &&
				csr_sub_type != CSR_CIPHER_RESPONSE &&
				csr_sub_type != CSR_SIGNER_RESPONSE) {
				ue_logger_warn("Invalid CSR sub type");
				continue;
			}

			if (!ue_byte_read_next_int(response, &csr_response_size)) {
				ue_stacktrace_push_msg("Failed to read CSR response size in response");
				goto clean_up;
			}
			if (!ue_byte_read_next_bytes(response, &csr_response, (size_t)csr_response_size)) {
				ue_stacktrace_push_msg("Failed to read CSR response in response");
				goto clean_up;
			}

			if (csr_sub_type == CSR_TLS_RESPONSE) {
				ue_logger_trace("Received CSR_TLS_RESPONSE");

				if (!(client_channel->tls_csr_context->signed_certificate = ue_csr_process_server_response(csr_response,
					(size_t)csr_response_size, client_channel->tls_csr_context->future_key, client_channel->tls_csr_context->iv,
					client_channel->tls_csr_context->iv_size))) {

					ue_stacktrace_push_msg("Failed to process CSR TLS response");
				} else {
					client_channel->tls_keystore_ok = true;
				}
			}
			else if (csr_sub_type == CSR_CIPHER_RESPONSE) {
				ue_logger_trace("Received CSR_CIPHER_RESPONSE");

				if (!(client_channel->cipher_csr_context->signed_certificate = ue_csr_process_server_response(csr_response,
					(size_t)csr_response_size, client_channel->cipher_csr_context->future_key, client_channel->cipher_csr_context->iv,
					client_channel->cipher_csr_context->iv_size))) {

					ue_stacktrace_push_msg("Failed to process CSR CIPHER response");
				} else {
					client_channel->cipher_keystore_ok = true;
				}
			}
			else if (csr_sub_type == CSR_SIGNER_RESPONSE) {
				ue_logger_trace("Received CSR_SIGNER_RESPONSE");

				if (!(client_channel->signer_csr_context->signed_certificate = ue_csr_process_server_response(csr_response,
					(size_t)csr_response_size, client_channel->signer_csr_context->future_key, client_channel->signer_csr_context->iv,
					client_channel->signer_csr_context->iv_size))) {

					ue_stacktrace_push_msg("Failed to process CSR SIGNER response");
				} else {
					client_channel->signer_keystore_ok = true;
				}
			}
		}

clean_up:
		ue_safe_free(csr_response);
		if (ue_stacktrace_is_filled()) {
			ue_stacktrace_push_msg("The processing of a client CSR failed");
			/* @todo send a response to the client in case of error */
			ue_logger_stacktrace("An error occured with the following stacktrace :");
			ue_stacktrace_clean_up();
		}

		if (client_channel->tls_keystore_ok && client_channel->cipher_keystore_ok && client_channel->signer_keystore_ok) {
			client_channel->running = false;
		}
	}

	result = true;

	return result;
}

static bool tls_read_consumer(void *parameter) {
	bool result;
	size_t received;
	int type;
	ue_byte_stream *stream;
	ue_socket_client_connection *connection;
	ue_socket_client_channel *client_channel;

	result = true;
	stream = ue_byte_stream_create();
	connection = (ue_socket_client_connection *)parameter;
	client_channel = connection->optional_data;

	while (client_channel->running) {
		received = receive_cipher_message(client_channel, connection);
		result = true;

		// @todo set timeout in case of server lag or reboot
		if (received <= 0 || received == ULLONG_MAX) {
			ue_logger_warn("Stopping client...");
			if (ue_stacktrace_is_filled()) {
				ue_logger_stacktrace("An error occured while receving a cipher message with the following stacktrace :");
				ue_stacktrace_clean_up();
			}
			client_channel->running = false;
			result = false;
		}
		else {
			ue_byte_stream_clean_up(stream);
			if (!ue_byte_writer_append_bytes(stream, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message))) {
				ue_logger_error("Failed to write received message to working stream");
				continue;
			}
			ue_byte_stream_set_position(stream, 0);

			ue_byte_read_next_int(stream, &type);

			if (type == ALREADY_CONNECTED_RESPONSE) {
				ue_logger_warn("Already connected");
				client_channel->running = false;
				result = false;
			}
			else if (type == NICKNAME_RESPONSE) {
				result = process_nickname_response(client_channel, stream);
				ue_logger_trace("Server has accepted this nickname.");
			}
			else if (type == CHANNEL_CONNECTION_RESPONSE) {
				ue_logger_trace("CHANNEL_CONNECTION_RESPONSE");
				result = process_channel_connection_response(client_channel, stream);
			}
			else if (type == MESSAGE && !client_channel->channel_key) {
				ue_logger_warn("Cannot decipher received message for now, because we doesn't have to channel key");
			}
			else if (type == MESSAGE && client_channel->channel_key) {
				ue_logger_trace("MESSAGE received");
				result = process_message_response(client_channel, stream);
			}
			else if (type == CERTIFICATE_RESPONSE) {
				result = process_certificate_response(client_channel, stream);
			}
			else if (type == CHANNEL_KEY_RESPONSE) {
				ue_logger_trace("CHANNEL_KEY_RESPONSE");
				result = process_channel_key_response(client_channel, connection, stream);
			}
			else if (type == CHANNEL_KEY_REQUEST && !client_channel->channel_key) {
				ue_logger_warn("Receive a channel key request but we doesn't have it");
			}
			else if (type == CHANNEL_KEY_REQUEST && client_channel->channel_key) {
				ue_logger_trace("CHANNEL_KEY_REQUEST");
				result = process_channel_key_request(client_channel, connection, stream);
			}
			else if (client_channel->channel_id >= 0 && !client_channel->channel_key) {
				ue_logger_warn("Cannot decrypt server data because we don't know channel key for now");
			} else {
				ue_logger_warn("Received invalid data type from server '%d'.", type);
			}
		}

		if (!result) {
			if (ue_stacktrace_is_filled()) {
				ue_stacktrace_push_msg("Failed to process server response");
				ue_logger_stacktrace("An error occured in this reading iteration with the following stacktrace :");
				ue_stacktrace_clean_up();
			}
		}
	}

	ue_byte_stream_destroy(stream);

	return result;
}

static bool tls_write_consumer(void *parameter) {
	bool result;
	char *input;
	ue_socket_client_connection *connection;
	int channel_id;
	ue_socket_client_channel *client_channel;

	result = true;
	input = NULL;
	connection = (ue_socket_client_connection *)parameter;
	client_channel = connection->optional_data;

    if (!send_nickname_request(client_channel, connection)) {
        ue_stacktrace_push_msg("Failed to send nickname request");
        return false;
    }

	while (client_channel->running) {
		if (ue_stacktrace_is_filled()) {
			ue_logger_stacktrace("An error occured in the last input iteration, with the following stacktrace :");
			ue_stacktrace_clean_up();
		}

		ue_safe_free(input);

		input = ue_input_string(">");

		if (!input) {
			continue;
		}

		channel_id = -1;
		ue_byte_stream_clean_up(connection->message_to_send);
		if (!ue_byte_writer_append_int(connection->message_to_send, client_channel->channel_id)) {
			ue_stacktrace_push_msg("Failed to write channel id to message to send");
			continue;
		}

		if (strcmp(input, "-q") == 0) {
			if (!ue_byte_writer_append_int(connection->message_to_send, DISCONNECTION_NOW_REQUEST)) {
				ue_stacktrace_push_msg("Failed to write DISCONNECTION_NOW_REQUEST type to message to send");
				continue;
			}
			ue_byte_writer_append_string(connection->message_to_send, "|||EOFEOFEOF");
			if (!(result = send_cipher_message(client_channel, connection, connection->message_to_send))) {
				ue_stacktrace_push_msg("Failed to send cipher message");
				continue;
			}
			client_channel->running = false;
		}
		else if (strcmp(input, "-s") == 0) {
			if (!ue_byte_writer_append_int(connection->message_to_send, SHUTDOWN_NOW_REQUEST)) {
				ue_stacktrace_push_msg("Failed to write SHUTDOWN_NOW_REQUEST type to message to send");
				continue;
			}
			ue_byte_writer_append_string(connection->message_to_send, "|||EOFEOFEOF");
			if (!(result = send_cipher_message(client_channel, connection, connection->message_to_send))) {
				ue_stacktrace_push_msg("Failed to send cipher message");
				continue;
			}
			client_channel->running = false;
		}
		else if (ue_starts_with("@channel_connection", input)) {
			if (!ue_string_to_int(input + strlen("@channel_connection") + 1, &channel_id, 10)) {
				ue_logger_warn("Specified channel id is invalid. Usage : --channel <number>");
			}
			else if (channel_id == -1) {
				ue_logger_warn("Specified channel id is invalid. It have to be >= 0");
			}
			else {
				if (!ue_byte_writer_append_int(connection->message_to_send, CHANNEL_CONNECTION_REQUEST)) {
					ue_stacktrace_push_msg("Failed to write CHANNEL_CONNECTION_REQUEST type to message to send");
					continue;
				}
				if (!ue_byte_writer_append_int(connection->message_to_send, channel_id)) {
					ue_stacktrace_push_msg("Failed to write channel id to message to send");
					continue;
				}
				if (!ue_byte_writer_append_string(connection->message_to_send, "|||EOFEOFEOF")) {
					ue_stacktrace_push_msg("Failed to write EOF delimiter to message to send");
					continue;
				}

				if (!(result = send_cipher_message(client_channel, connection, connection->message_to_send))) {
					ue_stacktrace_push_msg("Failed to send cipher message");
					continue;
				}
			}
		}
		else {
			if (!(result = process_message_request(client_channel, connection, input))) {
				ue_stacktrace_push_msg("Failed to process message request");
				continue;
			}
		}
	}

	ue_safe_free(input);

	return result;
}

static bool process_get_certificate_request(ue_socket_client_channel *client_channel, ue_pkcs12_keystore *keystore,
	ue_socket_client_connection *connection, const unsigned char *friendly_name, size_t friendly_name_size) {
	bool result;
	ue_byte_stream *request, *response;
	unsigned char *certificate_data;
	int type, certificate_data_size;

	ue_check_parameter_or_return(keystore);
	ue_check_parameter_or_return(connection);
	ue_check_parameter_or_return(friendly_name);
	ue_check_parameter_or_return(friendly_name_size > 0);

	result = false;
	request = ue_byte_stream_create();
	response = ue_byte_stream_create();
	certificate_data = NULL;

	if (!ue_byte_writer_append_int(request, client_channel->channel_id)) {
		ue_stacktrace_push_msg("Failed to write channel id to request");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(request, GET_CERTIFICATE_REQUEST)) {
		ue_stacktrace_push_msg("Failed to write GET_CERTIFICATE_REQUEST type to request");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(request, (int)friendly_name_size)) {
		ue_stacktrace_push_msg("Failed to write friendly name size to request");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(request, (unsigned char *)friendly_name, friendly_name_size)) {
		ue_stacktrace_push_msg("Failed to write friendly name to request");
		goto clean_up;
	}
	if (!ue_byte_writer_append_string(request, "|||EOFEOFEOF")) {
		ue_stacktrace_push_msg("Failed to write EOF delimiter to request");
		goto clean_up;
	}

	if (!send_cipher_message(client_channel, connection, request)) {
		ue_stacktrace_push_msg("Failed to send GET_CERTIFICATE request to server");
		goto clean_up;
	}

	connection->state = READING_STATE;
	if (receive_cipher_message(client_channel, connection) <= 0) {
		ue_stacktrace_push_msg("Failed to receive cipher message response of GET_CERTIFICATE request");
		goto clean_up;
	}

	if (!ue_byte_writer_append_bytes(response, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message))) {
		ue_stacktrace_push_msg("Failed to write received message to response");
		goto clean_up;
	}
	ue_byte_stream_set_position(response, 0);
	if (!ue_byte_read_next_int(response, &type)) {
		ue_stacktrace_push_msg("Failed to read request type in response");
		goto clean_up;
	}
	if (type != CERTIFICATE_RESPONSE) {
		ue_logger_error("GET_CERTIFICATE request received an invalid response type");
		goto clean_up;
	}

	if (!ue_byte_read_next_int(response, &certificate_data_size)) {
		ue_stacktrace_push_msg("Failed to read certificate data size in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(response, &certificate_data, (size_t)certificate_data_size)) {
		ue_stacktrace_push_msg("Failed to read certificate data in response");
		goto clean_up;
	}

	ue_logger_info("Missing certificate received. Trying to add it to the cipher keystore...");
	if (!(ue_pkcs12_keystore_add_certificate_from_bytes(keystore, certificate_data, (size_t)certificate_data_size,
		(const unsigned char *)friendly_name, friendly_name_size))) {

		ue_stacktrace_push_msg("Failed to add received certificate to cipher keystore");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_byte_stream_destroy(request);
	ue_byte_stream_destroy(response);
	ue_safe_free(certificate_data);
	return result;
}

static bool process_channel_key_request(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection,
	ue_byte_stream *request) {
	bool result;
	unsigned char *cipher_data, *friendly_name, *nickname;
	size_t cipher_data_size, friendly_name_size;
	ue_x509_certificate *client_certificate;
	ue_public_key *client_public_key;
	ue_byte_stream *channel_key_stream;
	int nickname_size;

	ue_check_parameter_or_return(connection);
	ue_check_parameter_or_return(request);

	result = false;
	client_certificate = NULL;
	cipher_data = NULL;
	friendly_name = NULL;
	client_public_key = NULL;
	nickname = NULL;
	channel_key_stream = ue_byte_stream_create();

	if (!ue_byte_read_next_int(request, &nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname size in request");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(request, &nickname, (size_t)nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname in request");
		goto clean_up;
	}

	if (!(friendly_name = ue_friendly_name_build(nickname, (size_t)nickname_size, "CIPHER", &friendly_name_size))) {
		ue_stacktrace_push_msg("Failed to build friendly name for CIPHER keystore");
		goto clean_up;
	}

	if (!(client_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(client_channel->cipher_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
		ue_logger_warn("Cipher certificate of client was not found. Requesting the server...");

		if (!process_get_certificate_request(client_channel, client_channel->cipher_keystore, connection, (const unsigned char *)friendly_name, friendly_name_size)) {
			ue_stacktrace_push_msg("Failed to get missing certificate");
			goto clean_up;
		}

		if (!ue_pkcs12_keystore_write(client_channel->cipher_keystore, client_channel->cipher_keystore_path, client_channel->keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", client_channel->cipher_keystore_path);
			goto clean_up;
		}

		ue_logger_info("Retrying find cipher certificate...");

		if (!(client_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(client_channel->cipher_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
			ue_stacktrace_push_msg("Failed to retreive client cipher certificate, while it should not happen");
			goto clean_up;
		}
	}

	if (!(client_public_key = ue_rsa_public_key_from_x509_certificate(client_certificate))) {
		ue_stacktrace_push_msg("Failed to extract public key of client cipher certificate");
		goto clean_up;
	}

	if (!ue_byte_writer_append_int(channel_key_stream, (int)client_channel->channel_key->size)) {
		ue_stacktrace_push_msg("Failed to write channel key size to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(channel_key_stream, (int)client_channel->channel_iv_size)) {
		ue_stacktrace_push_msg("Failed to write channel IV size to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(channel_key_stream, client_channel->channel_key->data, client_channel->channel_key->size)) {
		ue_stacktrace_push_msg("Failed to write channel key to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(channel_key_stream, client_channel->channel_iv, client_channel->channel_iv_size)) {
		ue_stacktrace_push_msg("Failed to write channel IV to stream");
		goto clean_up;
	}

	if (!ue_cipher_plain_data(ue_byte_stream_get_data(channel_key_stream), ue_byte_stream_get_size(channel_key_stream),
		   client_public_key, client_channel->signer_keystore->private_key, &cipher_data, &cipher_data_size, "aes-256-cbc")) {

		ue_stacktrace_push_msg("Failed to cipher plain data");
		goto clean_up;
	}

	// Build message to send : CHANNEL_KEY_REQUEST_ANSWER|<receiver_nickname>|<ciphered channel key>|
	ue_byte_stream_clean_up(channel_key_stream);
	if (!ue_byte_writer_append_int(channel_key_stream, client_channel->channel_id)) {
		ue_stacktrace_push_msg("Failed to write channel id to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(channel_key_stream, CHANNEL_KEY_REQUEST_ANSWER)) {
		ue_stacktrace_push_msg("Failed to write CHANNEL_KEY_REQUEST_ANSWER to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(channel_key_stream, nickname_size)) {
		ue_stacktrace_push_msg("Failed to write nickname size to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(channel_key_stream, nickname, (size_t)nickname_size)) {
		ue_stacktrace_push_msg("Failed to write nickname to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(channel_key_stream, (int)cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write cipher data size to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(channel_key_stream, cipher_data, cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write cipher data to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_string(channel_key_stream, "|||EOFEOFEOF")) {
		ue_stacktrace_push_msg("Failed to write EOF delimiter to response");
		goto clean_up;
	}

	if (!send_cipher_message(client_channel, connection, channel_key_stream)) {
		ue_stacktrace_push_msg("Send the stream in a cipher message failed");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_safe_free(cipher_data);
	ue_safe_free(friendly_name);
	ue_public_key_destroy(client_public_key);
	ue_byte_stream_destroy(channel_key_stream);
	ue_safe_free(nickname);
	return result;
}

static bool send_nickname_request(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection) {
	ue_check_parameter_or_return(connection);

	ue_byte_stream_clean_up(connection->message_to_send);
	if (!ue_byte_writer_append_int(connection->message_to_send, client_channel->channel_id)) {
		ue_stacktrace_push_msg("Failed to write channel id to message to send");
		return false;
	}
	if (!ue_byte_writer_append_int(connection->message_to_send, NICKNAME_REQUEST)) {
		ue_stacktrace_push_msg("Failed to write NICKNAME_REQUEST type to message to send");
		return false;
	}
	if (!ue_byte_writer_append_int(connection->message_to_send, (int)strlen(client_channel->nickname))) {
		ue_stacktrace_push_msg("Failed to write nickname size to message to send");
		return false;
	}
	if (!ue_byte_writer_append_bytes(connection->message_to_send, (unsigned char *)client_channel->nickname, strlen(client_channel->nickname))) {
		ue_stacktrace_push_msg("Failed to write nickname to message to send");
		return false;
	}
	if (!ue_byte_writer_append_string(connection->message_to_send, "|||EOFEOFEOF")) {
		ue_stacktrace_push_msg("Failed to write EOF delimiter to message to send");
		return false;
	}

    if (!send_message(client_channel, connection, connection->message_to_send)) {
        ue_stacktrace_push_msg("Failed to send nickname request");
        return false;
    }

	return true;
}

static bool process_message_request(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection, char *input) {
	bool result;
	ue_sym_encrypter *encrypter;
	unsigned char *cipher_data, *bytes_input;
	size_t cipher_data_size;

	ue_check_parameter_or_return(connection);
	ue_check_parameter_or_return(input);

	result = false;
	encrypter = NULL;
	cipher_data = NULL;
	bytes_input = NULL;

	if (client_channel->channel_id >= 0 && client_channel->channel_key) {
		ue_byte_writer_append_int(connection->message_to_send, MESSAGE);
		ue_byte_writer_append_int(connection->message_to_send, (int)strlen(client_channel->nickname));
		ue_byte_writer_append_bytes(connection->message_to_send, (unsigned char *)client_channel->nickname, (int)strlen(client_channel->nickname));

		bytes_input = ue_bytes_create_from_string(input);

		if (client_channel->channel_key) {
			if (!(encrypter = ue_sym_encrypter_default_create(client_channel->channel_key))) {
				ue_stacktrace_push_msg("Failed to create sym encrypter with this channel key");
				goto clean_up;
			}
			else if (!ue_sym_encrypter_encrypt(encrypter, bytes_input, strlen(input),
				client_channel->channel_iv, &cipher_data, &cipher_data_size)) {

				ue_stacktrace_push_msg("Failed to encrypt this input");
				goto clean_up;
			}
			else if (!ue_byte_writer_append_int(connection->message_to_send, (int)cipher_data_size)) {
				ue_stacktrace_push_msg("Failed to append cipher data size");
				goto clean_up;
			}
			else if (!ue_byte_writer_append_bytes(connection->message_to_send, cipher_data, cipher_data_size)) {
				ue_stacktrace_push_msg("Failed to append cipher data to message to send");
				goto clean_up;
			}
		} else {
			ue_byte_writer_append_string(connection->message_to_send, input);
		}

		ue_byte_writer_append_string(connection->message_to_send, "|||EOFEOFEOF");
		result = send_cipher_message(client_channel, connection, connection->message_to_send);
	}
	else if (client_channel->channel_id < 0) {
		ue_logger_warn("Cannot send message because no channel is selected");
	} else {
		ue_logger_warn("Cannot send message because we don't know channel key for now");
	}

	result = true;

clean_up:
	ue_sym_encrypter_destroy(encrypter);
	ue_safe_free(cipher_data);
	ue_safe_free(bytes_input);
	return result;
}

static bool process_nickname_response(ue_socket_client_channel *client_channel, ue_byte_stream *response) {
	bool result;
	int is_accepted;

	ue_check_parameter_or_return(response);

	result = false;

	if (!ue_byte_read_next_int(response, &is_accepted)) {
		ue_stacktrace_push_msg("Failed to read is accepted field in response");
		goto clean_up;
	}

	if (is_accepted == 0) {
		ue_logger_info("This nickname is already in use.");
		client_channel->running = false;
		goto clean_up;
	}
	else if (is_accepted != 1) {
		ue_logger_warn("Response of nickname request is incomprehensible.");
		client_channel->running = false;
		goto clean_up;
	}

	result = true;

clean_up:
	return result;
}

static bool process_channel_connection_response(ue_socket_client_channel *client_channel, ue_byte_stream *response) {
	bool result;
	int is_accepted, channel_key_state;

	result = false;

	ue_check_parameter_or_return(response);

	if (!ue_byte_read_next_int(response, &is_accepted)) {
		ue_stacktrace_push_msg("Failed to read is accepted field in response");
		goto clean_up;
	}

	if (is_accepted == 0) {
		ue_logger_info("This channel is already in use or cannot be use right now.");
		client_channel->running = false;
		goto clean_up;
	}
	else if (is_accepted != 1) {
		ue_logger_warn("Response of channel connection request is incomprehensible.");
		goto clean_up;
	} else {
		if (!ue_byte_read_next_int(response, &client_channel->channel_id)) {
			ue_stacktrace_push_msg("Failed to read channel id in response");
			goto clean_up;
		}
		ue_logger_trace("Channel connection has been accepted by the server with channel id %d.", client_channel->channel_id);

		if (!ue_byte_read_next_int(response, &channel_key_state)) {
			ue_stacktrace_push_msg("Failed to read channel key state in response");
			goto clean_up;
		}

		if (channel_key_state == CHANNEL_KEY_CREATOR_STATE) {
			ue_logger_info("Generate random channel key");
			client_channel->channel_key = ue_sym_key_create_random();
			ue_safe_alloc(client_channel->channel_iv, unsigned char, 16);
			if (!(ue_crypto_random_bytes(client_channel->channel_iv, 16))) {
				ue_stacktrace_push_msg("Failed to get crypto random bytes for IV");
				goto clean_up;
			}
			client_channel->channel_iv_size = 16;
		}
		else if (channel_key_state == WAIT_CHANNEL_KEY_STATE) {
			ue_logger_info("Waiting the channel key");
		}
		else {
			ue_logger_warn("Unknown channel key action type. Default is waiting the channel key");
			goto clean_up;
		}
	}

	result = true;

clean_up:
	return result;
}

static bool process_message_response(ue_socket_client_channel *client_channel, ue_byte_stream *message) {
	bool result;
	ue_sym_encrypter *decrypter;
	unsigned char *cipher_data, *decipher_data, *nickname;
	size_t decipher_data_size;
	int cipher_data_size, nickname_size;
	ue_byte_stream *printer;

	ue_check_parameter_or_return(message);

	result = false;
	decrypter = NULL;
	cipher_data = NULL;
	decipher_data = NULL;
	nickname = NULL;
	printer = ue_byte_stream_create();

	if (!ue_byte_read_next_int(message, &nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname size in message");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(message, &nickname, (size_t)nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname in message");
		goto clean_up;
	}
	if (!ue_byte_read_next_int(message, &cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to read cipher data size in message");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(message, &cipher_data, (size_t)cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to read cipher data in message");
		goto clean_up;
	}

	if (!ue_byte_writer_append_bytes(printer, nickname, (size_t)nickname_size)) {
		ue_stacktrace_push_msg("Failed to write nickname to printer");
		goto clean_up;
	}
	if (!ue_byte_writer_append_string(printer, ": ")) {
		ue_stacktrace_push_msg("Failed to write ':' delimiter to printer");
		goto clean_up;
	}

	if (!(decrypter = ue_sym_encrypter_default_create(client_channel->channel_key))) {
		ue_stacktrace_push_msg("Failed to create default sym decrypter with client_channel channel key");
		goto clean_up;
	}
	if  (!ue_sym_encrypter_decrypt(decrypter, cipher_data, (size_t)cipher_data_size,
		client_channel->channel_iv, &decipher_data, &decipher_data_size)) {
		ue_stacktrace_push_msg("Failed to decrypt cipher data");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(printer, decipher_data, decipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write decipher data to printer");
		goto clean_up;
	}

	if (!ue_byte_writer_append_bytes(printer, (unsigned char *)"\n\0", 2)) {
		ue_stacktrace_push_msg("Failed to write \n\0 to printer");
		goto clean_up;
	}

	if (!client_channel->write_consumer(printer)) {
		ue_logger_warn("Failed to write the message with user write consumer");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_sym_encrypter_destroy(decrypter);
	ue_safe_free(cipher_data);
	ue_safe_free(decipher_data);
	ue_safe_free(nickname);
	ue_byte_stream_destroy(printer);
	return result;
}

static bool process_certificate_response(ue_socket_client_channel *client_channel, ue_byte_stream *response) {
	bool result;
	ue_pkcs12_keystore *keystore;
	unsigned char *friendly_name, *certificate_data;
	int friendly_name_size, certificate_data_size;

	ue_check_parameter_or_return(response);
	ue_check_parameter_or_return(ue_byte_stream_get_size(response));

	result = false;
	keystore = NULL;
	friendly_name = NULL;
	certificate_data = NULL;

	if (!ue_byte_read_next_int(response, &friendly_name_size)) {
		ue_stacktrace_push_msg("Failed to read friendly name size in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(response, &friendly_name, (size_t)friendly_name_size)) {
		ue_stacktrace_push_msg("Failed to read friendly name in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_int(response, &certificate_data_size)) {
		ue_stacktrace_push_msg("Failed to read certificate data size in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(response, &certificate_data, (size_t)certificate_data_size)) {
		ue_stacktrace_push_msg("Failed to read certificate data in response");
		goto clean_up;
	}

	if (bytes_contains(friendly_name, friendly_name_size, (unsigned char *)"_CIPHER", strlen("_CIPHER"))) {
		keystore = client_channel->cipher_keystore;
	} else if (bytes_contains(friendly_name, friendly_name_size, (unsigned char *)"_SIGNER", strlen("_SIGNER"))) {
		keystore = client_channel->signer_keystore;
	} else {
		ue_logger_warn("Invalid friendly name in GET_CERTIFICATE request");
		goto clean_up;
	}

	if (!ue_pkcs12_keystore_add_certificate_from_bytes(keystore, certificate_data, certificate_data_size, friendly_name, friendly_name_size)) {
		ue_stacktrace_push_msg("Failed to add new certificate from bytes");
		goto clean_up;
	}

	result = true;

clean_up:
	return result;
}

static bool process_channel_key_response(ue_socket_client_channel *client_channel, ue_socket_client_connection *connection,
	ue_byte_stream *response) {
	bool result;
	ue_x509_certificate *key_owner_certificate;
	unsigned char *friendly_name, *plain_data, *key, *nickname, *cipher_data;
	ue_public_key *key_owner_public_key;
	ue_byte_stream *channel_key_stream;
	int key_size, nickname_size, cipher_data_size, read_int;
	size_t friendly_name_size, plain_data_size;

	ue_check_parameter_or_return(connection);
	ue_check_parameter_or_return(response);
	ue_check_parameter_or_return(ue_byte_stream_get_size(response) > 0);

	result = false;
	key_owner_certificate = NULL;
	friendly_name = NULL;
	plain_data = NULL;
	key = NULL;
	nickname = NULL;
	cipher_data = NULL;
	key_owner_public_key = NULL;
	channel_key_stream = ue_byte_stream_create();

	if (!ue_byte_read_next_int(response, &nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname size in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(response, &nickname, (size_t)nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname in response");
		goto clean_up;
	}

	if (!(friendly_name = ue_friendly_name_build(nickname, (size_t)nickname_size, "SIGNER", &friendly_name_size))) {
		ue_stacktrace_push_msg("Failed to build friendly name for SIGNER keystore");
		goto clean_up;
	}

	if (!(key_owner_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(client_channel->signer_keystore,
		(const unsigned char *)friendly_name, friendly_name_size))) {

		ue_logger_warn("Signer certificate of client was not found. Requesting the server...");

		if (!process_get_certificate_request(client_channel, client_channel->signer_keystore, connection, (const unsigned char *)friendly_name, friendly_name_size)) {
			ue_stacktrace_push_msg("Failed to get missing certificate");
			goto clean_up;
		}

		if (!ue_pkcs12_keystore_write(client_channel->signer_keystore, client_channel->signer_keystore_path, client_channel->keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", client_channel->signer_keystore_path);
			goto clean_up;
		}

		ue_logger_info("Retrying find signer certificate...");

		if (!(key_owner_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(client_channel->signer_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
			ue_stacktrace_push_msg("Failed to retreive client signer certificate, while it should not happen");
			goto clean_up;
		}
	}

	if (!(key_owner_public_key = ue_rsa_public_key_from_x509_certificate(key_owner_certificate))) {
		ue_stacktrace_push_msg("Failed to get client public key from client certificate");
		goto clean_up;
	}

	if (!ue_byte_read_next_int(response, &cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to read cipher data size in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(response, &cipher_data, cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to read cipher data in response");
		goto clean_up;
	}

	if (!ue_decipher_cipher_data(cipher_data, cipher_data_size, client_channel->cipher_keystore->private_key,
		key_owner_public_key, &plain_data, &plain_data_size, "aes-256-cbc")) {

		ue_stacktrace_push_msg("Failed decipher message data");
		goto clean_up;
	}

	if (!ue_byte_writer_append_bytes(channel_key_stream, plain_data, plain_data_size)) {
		ue_stacktrace_push_msg("Failed to append plain data into channel key stream");
		goto clean_up;
	}
	ue_byte_stream_set_position(channel_key_stream, 0);

	if (!ue_byte_read_next_int(channel_key_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to read channel key size");
		goto clean_up;
	}
	key_size = (size_t)read_int;

	if (!ue_byte_read_next_int(channel_key_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to read channel iv size");
		goto clean_up;
	}
	client_channel->channel_iv_size = (size_t)read_int;

	if (!ue_byte_read_next_bytes(channel_key_stream, &key, key_size)) {
		ue_stacktrace_push_msg("Failed to read channel key bytes");
		goto clean_up;
	}

	if (!ue_byte_read_next_bytes(channel_key_stream, &client_channel->channel_iv, client_channel->channel_iv_size)) {
		ue_stacktrace_push_msg("Failed to read channel iv bytes");
		goto clean_up;
	}

	if (!(client_channel->channel_key = ue_sym_key_create(key, key_size))) {
		ue_stacktrace_push_msg("Failed to create sym key based on parsed deciphered data");
		goto clean_up;
	}

	ue_logger_info("Channel key successfully received.");

	result = true;

clean_up:
	ue_public_key_destroy(key_owner_public_key);
	ue_safe_free(friendly_name);
	ue_safe_free(plain_data);
	ue_safe_free(key);
	ue_safe_free(nickname);
	ue_safe_free(cipher_data);
	ue_byte_stream_destroy(channel_key_stream);
	return result;
}

static bool generate_certificate(ue_x509_certificate **certificate, ue_private_key **private_key) {
    bool result;
    ue_x509_certificate_parameters *parameters;

	result = false;
	parameters = NULL;

	if (!(parameters = ue_x509_certificate_parameters_create())) {
		ue_stacktrace_push_msg("Failed to create x509 parameters structure");
		return false;
	}

    if (!ue_x509_certificate_parameters_set_country(parameters, "FR")) {
		ue_stacktrace_push_msg("Failed to set C to x509 parameters");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_common_name(parameters, "CLIENT")) {
		ue_stacktrace_push_msg("Failed to set CN to x509 parameters");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_ca_type(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate as ca type");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_subject_key_identifier_as_hash(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate subject key identifier as hash");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_self_signed(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate as self signed");
		goto clean_up;
	}

    if (!ue_x509_certificate_generate(parameters, certificate, private_key)) {
		ue_stacktrace_push_msg("Failed to generate certificate and relative private key");
		goto clean_up;
	}

    result = true;

clean_up:
    ue_x509_certificate_parameters_destroy(parameters);
    return result;
}
