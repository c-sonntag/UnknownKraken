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

#ifndef UnknownKrakenUnknownEcho_CHANNEL_SERVER_PARAMETERS_H
#define UnknownKrakenUnknownEcho_CHANNEL_SERVER_PARAMETERS_H

#include <uk/unknownecho/protocol/api/channel/channel_server_parameters_struct.h>
#include <uk/unknownecho/network/api/communication/communication_type.h>
#include <uk/utils/ueum.h>

uk_ue_channel_server_parameters *uk_ue_channel_server_parameters_create(char *keystore_password, char *key_password);

void uk_ue_channel_server_parameters_destroy(uk_ue_channel_server_parameters *parameters);

bool uk_ue_channel_server_parameters_set_persistent_path(uk_ue_channel_server_parameters *parameters, char *persistent_path);

bool uk_ue_channel_server_parameters_set_csr_port(uk_ue_channel_server_parameters *parameters, int port);

bool uk_ue_channel_server_parameters_set_csl_port(uk_ue_channel_server_parameters *parameters, int port);

bool uk_ue_channel_server_parameters_set_channels_number(uk_ue_channel_server_parameters *parameters, int channels_number);

bool uk_ue_channel_server_parameters_set_user_context(uk_ue_channel_server_parameters *parameters, void *user_context);

bool uk_ue_channel_server_parameters_set_initialization_begin_callback(uk_ue_channel_server_parameters *parameters, bool (*initialization_begin_callback)(void *user_context));

bool uk_ue_channel_server_parameters_set_initialization_end_callback(uk_ue_channel_server_parameters *parameters, bool (*initialization_end_callback)(void *user_context));

bool uk_ue_channel_server_parameters_set_uninitialization_begin_callback(uk_ue_channel_server_parameters *parameters, bool (*uninitialization_begin_callback)(void *user_context));

bool uk_ue_channel_server_parameters_set_uninitialization_end_callback(uk_ue_channel_server_parameters *parameters, bool (*uninitialization_end_callback)(void *user_context));

bool uk_ue_channel_server_parameters_set_cipher_name(uk_ue_channel_server_parameters *parameters, const char *cipher_name);

bool uk_ue_channel_server_parameters_set_digest_name(uk_ue_channel_server_parameters *parameters, const char *digest_name);

bool uk_ue_channel_server_parameters_set_communication_type(uk_ue_channel_server_parameters *parameters, uk_ue_communication_type communication_type);

bool uk_ue_channel_server_parameters_build(uk_ue_channel_server_parameters *parameters);

#endif
