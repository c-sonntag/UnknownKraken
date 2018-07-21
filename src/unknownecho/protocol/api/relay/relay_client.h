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

#ifndef UNKNOWNECHO_RELAY_CLIENT_H
#define UNKNOWNECHO_RELAY_CLIENT_H

#include <unknownecho/protocol/api/relay/relay_client_struct.h>
#include <unknownecho/protocol/api/relay/relay_route_struct.h>
#include <unknownecho/protocol/api/relay/relay_received_message_struct.h>
#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <ueum/ueum.h>

ue_relay_client *ue_relay_client_create_from_route(ue_communication_metadata *our_communication_metadata, ue_relay_route *route);

ue_relay_client *ue_relay_client_create_as_relay(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata, uecm_crypto_metadata *our_crypto_metadata);

ue_relay_client *ue_relay_client_create_as_relay_from_connection(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata, uecm_crypto_metadata *our_crypto_metadata, void *read_connection,
    void *write_connection);

void ue_relay_client_destroy(ue_relay_client *client);

bool ue_relay_client_is_valid(ue_relay_client *client);

ue_communication_context *ue_relay_client_get_communication_context(ue_relay_client *client);

void *ue_relay_client_get_read_connection(ue_relay_client *client);

void *ue_relay_client_get_write_connection(ue_relay_client *client);

bool ue_relay_client_send_message(ue_relay_client *client, ueum_byte_stream *message);

bool ue_relay_client_relay_message(ue_relay_client *client, ue_relay_received_message *received_message);

bool ue_relay_client_receive_message(ue_relay_client *client, ueum_byte_stream *message);

#endif
