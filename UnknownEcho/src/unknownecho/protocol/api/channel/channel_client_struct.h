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

#ifndef UNKNOWNECHO_CHANNEL_CLIENT_STRUCT_H
#define UNKNOWNECHO_CHANNEL_CLIENT_STRUCT_H

#include <unknownecho/network/api/communication/communication_context.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

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
    uecm_x509_certificate *signed_certificate;
    uecm_private_key *private_key;
    uecm_sym_key *future_key;
    unsigned char *iv;
    size_t iv_size;
} uecm_csr_context;

typedef struct {
    ue_communication_context *communication_context;
    char *nickname, *keystore_password;
    void *communication_secure_layer_session;
    void *connection;
    ueum_thread_id *read_thread, *write_thread;
    ue_processing_state csr_processing_state;
    ueum_thread_mutex *mutex;
    ueum_thread_cond *cond;
    ueum_queue *push_mode_queue;
    ue_data_transmission_state transmission_state;
    bool running;
    ueum_byte_stream *new_message, *received_message, *message_to_send, *tmp_stream;
    int channel_id;
    uecm_x509_certificate *csr_server_certificate, *csl_server_certificate, *cipher_server_certificate, *signer_server_certificate;
    bool csl_keystore_ok, cipher_keystore_ok, signer_keystore_ok;
    uecm_csr_context *csl_csr_context, *cipher_csr_context, *signer_csr_context;
    uecm_pkcs12_keystore *csl_keystore, *cipher_keystore, *signer_keystore;
    const char *csr_server_certificate_path;
    const char *csl_server_certificate_path;
    const char *cipher_server_certificate_path;
    const char *signer_server_certificate_path;
    const char *csl_keystore_path;
    const char *cipher_keystore_path;
    const char *signer_keystore_path;
    uecm_sym_key *channel_key;
    unsigned char *channel_iv;
    size_t channel_iv_size;
    FILE *logs_file;
    char *persistent_path, *csl_server_host;
    int csl_server_port;
    void *user_context;
    bool (*write_callback)(void *user_context, ueum_byte_stream *printer);
    bool (*initialization_begin_callback)(void *user_context);
    bool (*initialization_end_callback)(void *user_context);
    bool (*uninitialization_begin_callback)(void *user_context);
    bool (*uninitialization_end_callback)(void *user_context);
    bool (*connection_begin_callback)(void *user_context);
    bool (*connection_end_callback)(void *user_context);
    char *(*user_input_callback)(void *user_context);
    const char *cipher_name, *digest_name;
    ueum_user_input_mode user_input_mode;
} ue_channel_client;

#endif
