/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
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
    CSR_CSL_REQUEST             = 13,
    CSR_CIPHER_REQUEST          = 14,
    CSR_SIGNER_REQUEST          = 15,
    CERTIFICATE_RESPONSE        = 16,
    NICKNAME_RESPONSE           = 17,
    CSR_CSL_RESPONSE            = 18,
    CSR_CIPHER_RESPONSE         = 19,
    CSR_SIGNER_RESPONSE         = 20
} ue_channel_message_type;

#endif
