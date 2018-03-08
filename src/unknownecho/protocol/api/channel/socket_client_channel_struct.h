#ifndef UNKNOWNECHO_SOCKET_CLIENT_CHANNEL_STRUCT_H
#define UNKNOWNECHO_SOCKET_CLIENT_CHANNEL_STRUCT_H

#include <unknownecho/network/api/tls/tls_session.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/bool.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/crypto/api/key/private_key.h>

#include <stdio.h>
#include <stddef.h>

/* @todo put into the main struct */
typedef enum {
	READING_STATE,
	WRITING_STATE,
	CLOSING_STATE
} data_transmission_state;

/* @todo put into the main struct */
typedef struct {
	ue_x509_certificate *signed_certificate;
	ue_private_key *private_key;
	ue_sym_key *future_key;
	unsigned char *iv;
	size_t iv_size;
} csr_context;

typedef struct {
	int fd;
	char *nickname, *keystore_password;
	ue_tls_session *tls_session;
	ue_socket_client_connection *connection;
	ue_thread_id *read_thread, *write_thread;
	ue_thread_mutex *mutex;
	ue_thread_cond *cond;
	data_transmission_state transmission_state;
	bool running;
	ue_byte_stream *new_message;
	int channel_id;
	ue_x509_certificate *csr_server_certificate, *tls_server_certificate, *cipher_server_certificate, *signer_server_certificate;
	bool tls_keystore_ok, cipher_keystore_ok, signer_keystore_ok;
	csr_context *tls_csr_context, *cipher_csr_context, *signer_csr_context;
	ue_pkcs12_keystore *tls_keystore, *cipher_keystore, *signer_keystore;
	const char *csr_server_certificate_path;
	const char *tls_server_certificate_path;
	const char *cipher_server_certificate_path;
	const char *signer_server_certificate_path;
	const char *tls_keystore_path;
	const char *cipher_keystore_path;
	const char *signer_keystore_path;
	ue_sym_key *channel_key;
	unsigned char *channel_iv;
	size_t channel_iv_size;
	FILE *logs_file;
	char *root_path, *tls_server_host;
	int tls_server_port;
	bool (*write_consumer)(ue_byte_stream *printer);
} ue_socket_client_channel;

#endif
