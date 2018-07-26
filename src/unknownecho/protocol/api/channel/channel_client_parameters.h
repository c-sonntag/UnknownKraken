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

#ifndef UNKNOWNECHO_CHANNEL_CLIENT_PARAMETERS_H
#define UNKNOWNECHO_CHANNEL_CLIENT_PARAMETERS_H

#include <unknownecho/protocol/api/channel/channel_client_parameters_struct.h>
#include <unknownecho/protocol/api/channel/channel_client_struct.h>
#include <unknownecho/network/api/communication/communication_type.h>
#include <ueum/ueum.h>

ue_channel_client_parameters *ue_channel_client_parameters_create(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, ueum_byte_stream *printer));

void ue_channel_client_parameters_destroy(ue_channel_client_parameters *parameters);

bool ue_channel_client_parameters_set_persistent_path(ue_channel_client_parameters *parameters, char *persistent_path);

bool ue_channel_client_parameters_set_csr_host(ue_channel_client_parameters *parameters, const char *host);

bool ue_channel_client_parameters_set_csr_port(ue_channel_client_parameters *parameters, int port);

bool ue_channel_client_parameters_set_csl_host(ue_channel_client_parameters *parameters, const char *host);

bool ue_channel_client_parameters_set_csl_port(ue_channel_client_parameters *parameters, int port);

bool ue_channel_client_parameters_set_certificates_path(ue_channel_client_parameters *parameters, const char *certificates_path);

bool ue_channel_client_parameters_set_user_context(ue_channel_client_parameters *parameters, void *user_context);

bool ue_channel_client_parameters_set_initialization_begin_callback(ue_channel_client_parameters *parameters, bool (*initialization_begin_callback)(void *user_context));

bool ue_channel_client_parameters_set_initialization_end_callback(ue_channel_client_parameters *parameters, bool (*initialization_end_callback)(void *user_context));

bool ue_channel_client_parameters_set_uninitialization_begin_callback(ue_channel_client_parameters *parameters, bool (*uninitialization_begin_callback)(void *user_context));

bool ue_channel_client_parameters_set_uninitialization_end_callback(ue_channel_client_parameters *parameters, bool (*uninitialization_end_callback)(void *user_context));

bool ue_channel_client_parameters_set_connection_begin_callback(ue_channel_client_parameters *parameters, bool (*connection_begin_callback)(void *user_context));

bool ue_channel_client_parameters_set_connection_end_callback(ue_channel_client_parameters *parameters, bool (*connection_end_callback)(void *user_context));

bool ue_channel_client_parameters_set_user_input_callback(ue_channel_client_parameters *parameters, char *(*user_input_callback)(void *user_context));

bool ue_channel_client_parameters_set_cipher_name(ue_channel_client_parameters *parameters, const char *cipher_name);

bool ue_channel_client_parameters_set_digest_name(ue_channel_client_parameters *parameters, const char *digest_name);

bool ue_channel_client_parameters_set_user_input_mode(ue_channel_client_parameters *parameters, ueum_user_input_mode user_input_mode);

bool ue_channel_client_parameters_set_communication_type(ue_channel_client_parameters *parameters, ue_communication_type communication_type);

ue_channel_client *ue_channel_client_parameters_build(ue_channel_client_parameters *parameters);

#endif
