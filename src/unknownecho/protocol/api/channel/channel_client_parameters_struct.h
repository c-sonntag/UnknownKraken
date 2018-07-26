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

#ifndef UNKNOWNECHO_CHANNEL_CLIENT_PARAMETERS_STRUCT_H
#define UNKNOWNECHO_CHANNEL_CLIENT_PARAMETERS_STRUCT_H

#include <unknownecho/network/api/communication/communication_type.h>
#include <ueum/ueum.h>

typedef struct {
    char *persistent_path;
    char *nickname;
    const char *csr_server_host;
    int csr_server_port;
    const char *csl_server_host;
    int csl_server_port;
    char *keystore_password;
    const char *server_certificates_path;
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
    ue_communication_type communication_type;
} ue_channel_client_parameters;

#endif
