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

#ifndef UNKNOWNECHO_CHANNEL_CLIENT_H
#define UNKNOWNECHO_CHANNEL_CLIENT_H

#include <unknownecho/bool.h>
#include <unknownecho/protocol/api/channel/channel_client_struct.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/console/input.h>
#include <unknownecho/network/api/communication/communication_type.h>

#include <stddef.h>

bool ue_channel_client_init(int channel_clients_number);

void ue_channel_client_uninit();

ue_channel_client *ue_channel_client_create(char *persistent_path, char *nickname, const char *csr_server_host, int csr_server_port,
    const char *csl_server_host, int csl_server_port, char *keystore_password, const char *server_certificates_path, void *user_context,
	bool (*write_callback)(void *user_context, ue_byte_stream *printer), bool (*initialization_begin_callback)(void *user_context),
	bool (*initialization_end_callback)(void *user_context), bool (*uninitialization_begin_callback)(void *user_context),
	bool (*uninitialization_end_callback)(void *user_context), bool (*connection_begin_callback)(void *user_context),
	bool (*connection_end_callback)(void *user_context), char *(*user_input_callback)(void *user_context),
    const char *cipher_name, const char *digest_name, ue_user_input_mode user_input_mode, ue_communication_type communication_type);

void ue_channel_client_destroy(ue_channel_client *channel_client);

bool ue_channel_client_start(ue_channel_client *channel_client);

void ue_channel_client_shutdown_signal_callback(int sig);

bool ue_channel_client_set_user_input_mode(ue_channel_client *channel_client, ue_user_input_mode mode);

bool ue_channel_client_push_message(ue_channel_client *channel_client, unsigned char *data, size_t data_size);

#endif
