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

#ifndef UNKNOWNECHO_CHANNEL_CLIENT_FACTORY_H
#define UNKNOWNECHO_CHANNEL_CLIENT_FACTORY_H

#include <unknownecho/protocol/api/channel/channel_client_struct.h>
#include <ueum/ueum.h>

ue_channel_client *ue_channel_client_create_default_local(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, ueum_byte_stream *printer));

ue_channel_client *ue_channel_client_create_default_remote(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, ueum_byte_stream *printer),
    const char *host);

#endif
