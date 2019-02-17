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

#ifndef UnknownKrakenUnknownEcho_CHANNEL_SERVER_PARAMETERS_STRUCT_H
#define UnknownKrakenUnknownEcho_CHANNEL_SERVER_PARAMETERS_STRUCT_H

#include <uk/unknownecho/network/api/communication/communication_type.h>
#include <uk/utils/ueum.h>

typedef struct {
    char *persistent_path;
    int csr_server_port;
    int csl_server_port;
    char *keystore_password;
    int channels_number;
    char *key_password;
    void *user_context;
    bool (*initialization_begin_callback)(void *user_context);
    bool (*initialization_end_callback)(void *user_context);
    bool (*uninitialization_begin_callback)(void *user_context);
    bool (*uninitialization_end_callback)(void *user_context);
    const char *cipher_name, *digest_name;
    uk_ue_communication_type communication_type;
} uk_ue_channel_server_parameters;

#endif
