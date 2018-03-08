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

#ifndef UNKNOWNECHO_CHANNEL_MESSAGE_TYPE_H
#define UNKNOWNECHO_CHANNEL_MESSAGE_TYPE_H

typedef enum {
    CHANNEL_KEY_REQUEST         = 1,
    DISCONNECTION_NOW_REQUEST   = 2,
    ALREADY_CONNECTED_RESPONSE  = 3,
    CHANNEL_CONNECTION_REQUEST  = 4,
    GET_CERTIFICATE_REQUEST     = 5,
    NICKNAME_REQUEST            = 6,
    CHANNEL_KEY_REQUEST_ANSWER  = 7,
    CHANNEL_CONNECTION_RESPONSE = 8,
    CHANNEL_KEY_RESPONSE        = 9,
    CHANNEL_KEY_CREATOR_STATE   = 10,
    WAIT_CHANNEL_KEY_STATE      = 11,
    MESSAGE                     = 12,
    CSR_TLS_REQUEST             = 13,
    CSR_CIPHER_REQUEST          = 14,
    CSR_SIGNER_REQUEST          = 15,
    CERTIFICATE_RESPONSE        = 16,
    NICKNAME_RESPONSE           = 17,
    CSR_TLS_RESPONSE            = 18,
    CSR_CIPHER_RESPONSE         = 19,
    CSR_SIGNER_RESPONSE         = 20
} ue_channel_message_type;

#endif
