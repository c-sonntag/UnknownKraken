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

#include <unknownecho/protocol/api/relay/relay_received_message.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <ueum/ueum.h>

ue_relay_received_message *ue_relay_received_message_create_empty() {
    ue_relay_received_message *received_message;

    received_message = NULL;

    ueum_safe_alloc(received_message, ue_relay_received_message, 1);
    received_message->next_step = NULL;
    received_message->payload = NULL;
    received_message->remaining_encoded_route = NULL;
    received_message->remaining_encoded_back_route = NULL;
    received_message->unsealed_payload = false;

    return received_message;
}

void ue_relay_received_message_destroy(ue_relay_received_message *received_message) {
    if (received_message) {
        ue_relay_step_destroy(received_message->next_step);
        ueum_byte_stream_destroy(received_message->payload);
        ueum_byte_stream_destroy(received_message->remaining_encoded_route);
        ueum_byte_stream_destroy(received_message->remaining_encoded_back_route);
        ueum_safe_free(received_message);
    }
}
