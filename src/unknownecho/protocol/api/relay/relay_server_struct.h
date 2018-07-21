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

#ifndef UNKNOWNECHO_RELAY_SERVER_STRUCT_H
#define UNKNOWNECHO_RELAY_SERVER_STRUCT_H

#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/protocol/api/relay/relay_client_struct.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

typedef struct {
    ue_communication_metadata *our_communication_metadata;
    ue_communication_context *communication_context;
    void *communication_server;
    ueum_thread_id *server_thread;
    uecm_crypto_metadata *our_crypto_metadata;
    void *user_context;
    bool (*user_received_callback)(void *user_context, ueum_byte_stream *received_message);
    bool signal_caught;
    ue_relay_client **relay_clients;
    int relay_clients_number;
} ue_relay_server;

#endif
