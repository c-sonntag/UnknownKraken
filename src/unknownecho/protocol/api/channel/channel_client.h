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

bool ue_channel_client_init();

void ue_channel_client_uninit();

ue_channel_client *ue_channel_client_create(char *root_path, char *nickname, const char *csr_server_host, int csr_server_port,
	const char *tls_server_host, int tls_server_port, char *keystore_password, bool (*write_consumer)(ue_byte_stream *printer));

void ue_channel_client_destroy(ue_channel_client *channel_client);

bool ue_channel_client_start(ue_channel_client *channel_client);

#endif
