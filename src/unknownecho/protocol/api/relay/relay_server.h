/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#ifndef UNKNOWNECHO_RELAY_SERVER_H
#define UNKNOWNECHO_RELAY_SERVER_H

#include <unknownecho/protocol/api/relay/relay_server_struct.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

ue_relay_server *ue_relay_server_create(ue_communication_metadata *communication_metadata, void *user_context,
    uecm_crypto_metadata *our_crypto_metadata, bool (*user_received_callback)(void *user_context, ueum_byte_stream *received_message));

void ue_relay_server_destroy(ue_relay_server *relay_server);

bool ue_relay_server_is_valid(ue_relay_server *relay_server);

bool ue_relay_server_start(ue_relay_server *relay_server);

bool ue_relay_server_stop(ue_relay_server *relay_server);

bool ue_relay_server_wait(ue_relay_server *relay_server);

ue_communication_context *ue_relay_server_get_communication_context(ue_relay_server *relay_server);

void *ue_relay_server_get_communication_server(ue_relay_server *relay_server);

void ue_relay_server_shutdown_signal_callback(int sig);

#endif
