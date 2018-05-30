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

#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/protocol/api/channel/channel.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/bool.h>

#include <uv.h>

#include <stdio.h>
#include <stddef.h>

typedef enum {
    WORKING_STATE,
    FREE_STATE
} ue_processing_state;

typedef struct {
    void *csr_server, *csl_server;
    uv_mutex_t csr_server_mutex, csl_server_mutex;
    uv_cond_t csr_server_cond, csl_server_cond;
    ue_processing_state csr_server_processing_state, csl_server_processing_state;
    ue_communication_context *communication_context;
    void *communication_secure_layer_session;
    ue_channel **channels;
    int channels_number;
    uv_thread_t csr_server_thread, csl_server_thread;
    bool signal_caught;
    char *keystore_password;
    ue_pkcs12_keystore *csr_keystore, *csl_keystore, *cipher_keystore, *signer_keystore;
    FILE *logs_file;
    char *persistent_path, *csr_server_certificate_path, *csr_server_key_path,
        *csl_server_certificate_path, *csl_server_key_path, *cipher_server_certificate_path,
        *cipher_server_key_path, *signer_server_certificate_path, *signer_server_key_path,
        *csr_keystore_path, *csl_keystore_path, *cipher_keystore_path,
        *signer_keystore_path, *csr_server_port, *csl_server_port, *logger_file_path;
    char *key_passphrase;
    void *user_context;
    bool (*initialization_begin_callback)(void *user_context);
	bool (*initialization_end_callback)(void *user_context);
	bool (*uninitialization_begin_callback)(void *user_context);
	bool (*uninitialization_end_callback)(void *user_context);
    const char *cipher_name, *digest_name;
} ue_channel_server;

#endif
