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

#ifndef UnknownKrakenUnknownEcho_CHANNEL_CLIENT_FACTORY_H
#define UnknownKrakenUnknownEcho_CHANNEL_CLIENT_FACTORY_H

#include <uk/unknownecho/protocol/api/channel/channel_client_struct.h>
#include <uk/utils/ueum.h>

uk_ue_channel_client *uk_ue_channel_client_create_default_local(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, uk_utils_byte_stream *printer));

uk_ue_channel_client *uk_ue_channel_client_create_default_remote(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, uk_utils_byte_stream *printer),
    const char *host);

#endif
