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

#include <unknownecho/protocol/api/relay/relay_message_id.h>

bool ue_relay_message_id_is_valid(int id) {
    return id == UNKNOWNECHO_RELAY_MESSAGE_ID_ESTABLISH ||
        id == UNKNOWNECHO_RELAY_MESSAGE_ID_DISCONNECT ||
        id == UNKNOWNECHO_RELAY_MESSAGE_ID_REQUEST ||
        id == UNKNOWNECHO_RELAY_MESSAGE_ID_RESPONSE ||
        id == UNKNOWNECHO_RELAY_MESSAGE_ID_RELAY;
}
