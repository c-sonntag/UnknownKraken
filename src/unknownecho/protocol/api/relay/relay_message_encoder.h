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

#ifndef UNKNOWNECHO_RELAY_MESSAGE_ENCODER_H
#define UNKNOWNECHO_RELAY_MESSAGE_ENCODER_H

#include <unknownecho/protocol/api/relay/relay_route_struct.h>
#include <unknownecho/protocol/api/relay/relay_message_id.h>
#include <unknownecho/protocol/api/relay/relay_received_message_struct.h>
#include <ueum/ueum.h>

ueum_byte_stream *ue_relay_message_encode(ue_relay_route *route, ue_relay_route *back_route,
    ue_relay_message_id message_id, ueum_byte_stream *payload);

ueum_byte_stream *ue_relay_message_encode_from_encoded_route(ueum_byte_stream *encoded_route,
    ueum_byte_stream *encoded_back_route, ue_relay_message_id message_id, ueum_byte_stream *payload,
    ue_relay_step *payload_receiver);

ueum_byte_stream *ue_relay_message_encode_relay(ue_relay_received_message *received_message);

#endif
