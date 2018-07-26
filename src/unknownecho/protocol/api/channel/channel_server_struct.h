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

#ifndef UNKNOWNECHO_CHANNEL_SERVER_STRUCT_H
#define UNKNOWNECHO_CHANNEL_SERVER_STRUCT_H

#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/protocol/api/channel/channel.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

#include <stdio.h>
#include <stddef.h>

typedef enum {
    WORKING_STATE,
    FREE_STATE
} ue_processing_state;

typedef struct {
    void *csr_server, *csl_server;
    ueum_thread_mutex *csr_server_mutex, *csl_server_mutex;
    ueum_thread_cond *csr_server_cond, *csl_server_cond;
    ue_processing_state csr_server_processing_state, csl_server_processing_state;
    ue_communication_context *communication_context;
    void *communication_secure_layer_session;
    ue_channel **channels;
    int channels_number;
    ueum_thread_id *csr_server_thread, *csl_server_thread;
    bool signal_caught;
    char *keystore_password;
    uecm_pkcs12_keystore *csr_keystore, *csl_keystore, *cipher_keystore, *signer_keystore;
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
