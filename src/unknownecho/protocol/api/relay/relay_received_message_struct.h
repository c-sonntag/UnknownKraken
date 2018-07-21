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

#ifndef UNKNOWNECHO_RELAY_RECEIVED_MESSAGE_STRUCT_H
#define UNKNOWNECHO_RELAY_RECEIVED_MESSAGE_STRUCT_H

#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <unknownecho/protocol/api/relay/relay_message_id.h>
#include <unknownecho/protocol/api/protocol_id.h>
#include <ueum/ueum.h>

typedef struct {
    ueum_byte_stream *payload;
    ue_relay_step *next_step;
    ue_protocol_id protocol_id;
    ue_relay_message_id message_id;
    ueum_byte_stream *remaining_encoded_route, *remaining_encoded_back_route;
    bool unsealed_payload;
} ue_relay_received_message;

#endif
