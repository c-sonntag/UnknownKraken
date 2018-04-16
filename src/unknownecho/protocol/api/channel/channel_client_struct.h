/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#ifndef UNKNOWNECHO_CHANNEL_CLIENT_STRUCT_H
#define UNKNOWNECHO_CHANNEL_CLIENT_STRUCT_H

#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/bool.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/container/queue.h>
#include <unknownecho/console/input.h>

#include <stdio.h>
#include <stddef.h>

/* @todo put into the main struct */
typedef enum {
	READING_STATE,
	WRITING_STATE,
	CLOSING_STATE
} ue_data_transmission_state;

typedef enum {
    WORKING_STATE,
    FREE_STATE
} ue_processing_state;

/* @todo put into the main struct */
typedef struct {
	ue_x509_certificate *signed_certificate;
	ue_private_key *private_key;
	ue_sym_key *future_key;
	unsigned char *iv;
	size_t iv_size;
} ue_csr_context;

typedef struct {
    ue_communication_context *communication_context;
	char *nickname, *keystore_password;
    void *communication_secure_layer_session;
    void *connection;
	ue_thread_id *read_thread, *write_thread;
	ue_processing_state csr_processing_state;
    ue_thread_mutex *mutex;
    ue_thread_cond *cond;
    ue_queue *push_mode_queue;
	ue_data_transmission_state transmission_state;
	bool running;
    ue_byte_stream *new_message, *received_message, *message_to_send, *tmp_stream;
	int channel_id;
    ue_x509_certificate *csr_server_certificate, *csl_server_certificate, *cipher_server_certificate, *signer_server_certificate;
    bool csl_keystore_ok, cipher_keystore_ok, signer_keystore_ok;
    ue_csr_context *csl_csr_context, *cipher_csr_context, *signer_csr_context;
    ue_pkcs12_keystore *csl_keystore, *cipher_keystore, *signer_keystore;
	const char *csr_server_certificate_path;
    const char *csl_server_certificate_path;
	const char *cipher_server_certificate_path;
	const char *signer_server_certificate_path;
    const char *csl_keystore_path;
	const char *cipher_keystore_path;
	const char *signer_keystore_path;
	ue_sym_key *channel_key;
	unsigned char *channel_iv;
	size_t channel_iv_size;
	FILE *logs_file;
    char *persistent_path, *csl_server_host;
    int csl_server_port;
	void *user_context;
	bool (*write_callback)(void *user_context, ue_byte_stream *printer);
	bool (*initialization_begin_callback)(void *user_context);
	bool (*initialization_end_callback)(void *user_context);
	bool (*uninitialization_begin_callback)(void *user_context);
	bool (*uninitialization_end_callback)(void *user_context);
	bool (*connection_begin_callback)(void *user_context);
	bool (*connection_end_callback)(void *user_context);
	char *(*user_input_callback)(void *user_context);
	const char *cipher_name, *digest_name;
    ue_user_input_mode user_input_mode;
} ue_channel_client;

#endif
