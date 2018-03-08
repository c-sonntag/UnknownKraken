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

#ifndef UNKNOWNECHO_CHANNEL_SERVER_STRUCT_H
#define UNKNOWNECHO_CHANNEL_SERVER_STRUCT_H

#include <unknownecho/network/api/socket/socket_server.h>
#include <unknownecho/network/api/tls/tls_session.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/protocol/api/channel/channel.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/bool.h>

#include <stdio.h>

typedef enum {
    WORKING_STATE,
    FREE_STATE
} ue_processing_state;

typedef struct {
    ue_socket_server *csr_server, *tls_server;
	ue_thread_mutex *csr_server_mutex, *tls_server_mutex;
	ue_thread_cond *csr_server_cond, *tls_server_cond;
	ue_processing_state csr_server_processing_state, tls_server_processing_state;
	ue_tls_session *tls_session;
    ue_channel **channels;
    int channels_number;
    ue_thread_id *csr_server_thread, *tls_server_thread;
    bool signal_caught;
    char *keystore_password;
    ue_pkcs12_keystore *csr_keystore, *tls_keystore, *cipher_keystore, *signer_keystore;
    FILE *logs_file;
    char *persistent_path, *csr_server_certificate_path, *csr_server_key_path,
        *tls_server_certificate_path, *tls_server_key_path, *cipher_server_certificate_path,
        *cipher_server_key_path, *signer_server_certificate_path, *signer_server_key_path,
        *server_key_password, *csr_keystore_path, *tls_keystore_path, *cipher_keystore_path,
        *signer_keystore_path, *csr_server_port, *tls_server_port, *logger_file_path;
    void *user_context;
    bool (*initialization_begin_callback)(void *user_context);
	bool (*initialization_end_callback)(void *user_context);
	bool (*uninitialization_begin_callback)(void *user_context);
	bool (*uninitialization_end_callback)(void *user_context);
} ue_channel_server;

#endif
