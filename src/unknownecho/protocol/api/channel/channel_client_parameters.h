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

#ifndef UNKNOWNECHO_CHANNEL_CLIENT_PARAMETERS_H
#define UNKNOWNECHO_CHANNEL_CLIENT_PARAMETERS_H

#include <unknownecho/protocol/api/channel/channel_client_parameters_struct.h>
#include <unknownecho/protocol/api/channel/channel_client_struct.h>
#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_stream.h>

ue_channel_client_parameters *ue_channel_client_parameters_create(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, ue_byte_stream *printer));

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

bool ue_channel_client_parameters_set_user_input_mode(ue_channel_client_parameters *parameters, ue_user_input_mode user_input_mode);

bool ue_channel_client_parameters_set_communication_type(ue_channel_client_parameters *parameters, const char *communication_type);

ue_channel_client *ue_channel_client_parameters_build(ue_channel_client_parameters *parameters);

#endif
