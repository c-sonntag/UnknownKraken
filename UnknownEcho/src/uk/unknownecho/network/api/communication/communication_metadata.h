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

#ifndef UnknownKrakenUnknownEcho_COMMUNICATION_METADATA_H
#define UnknownKrakenUnknownEcho_COMMUNICATION_METADATA_H

#include <uk/unknownecho/network/api/communication/communication_type.h>
#include <uk/utils/ueum.h>

#include <stdio.h>

typedef enum {
    UnknownKrakenUnknownEcho_RELAY_SERVER,
    UnknownKrakenUnknownEcho_RELAY_CLIENT
} uk_ue_communication_destination_type;

typedef struct {
    const char *uid;
    uk_ue_communication_type type;
    const char *host;
    unsigned int port;
    uk_ue_communication_destination_type destination_type;
} uk_ue_communication_metadata;

uk_ue_communication_metadata *uk_ue_communication_metadata_create_empty();

uk_ue_communication_metadata *uk_ue_communication_metadata_create_from_string(const char *string);

void uk_ue_communication_metadata_destroy(uk_ue_communication_metadata *metadata);

void uk_ue_communication_metadata_clean_up(uk_ue_communication_metadata *metadata);

uk_ue_communication_metadata *uk_ue_communication_metadata_copy(uk_ue_communication_metadata *metadata);

const char *uk_ue_communication_metadata_get_uid(uk_ue_communication_metadata *metadata);

bool uk_ue_communication_metadata_set_uid(uk_ue_communication_metadata *metadata, const char *uid);

uk_ue_communication_type uk_ue_communication_metadata_get_type(uk_ue_communication_metadata *metadata);

bool uk_ue_communication_metadata_set_type(uk_ue_communication_metadata *metadata, uk_ue_communication_type type);

const char *uk_ue_communication_metadata_get_host(uk_ue_communication_metadata *metadata);

bool uk_ue_communication_metadata_set_host(uk_ue_communication_metadata *metadata, const char *host);

unsigned int uk_ue_communication_metadata_get_port(uk_ue_communication_metadata *metadata);

bool uk_ue_communication_metadata_set_port(uk_ue_communication_metadata *metadata, unsigned int port);

uk_ue_communication_destination_type uk_ue_communication_metadata_get_destination_type(uk_ue_communication_metadata *metadata);

bool uk_ue_communication_metadata_set_destination_type(uk_ue_communication_metadata *metadata, uk_ue_communication_destination_type destination_type);

bool uk_ue_communication_metadata_is_valid(uk_ue_communication_metadata *metadata);

const char *uk_ue_communication_metadata_to_string(uk_ue_communication_metadata *metadata);

bool uk_ue_communication_metadata_print(uk_ue_communication_metadata *metadata, FILE *fd);

bool uk_ue_communication_metadata_equals(uk_ue_communication_metadata *m1, uk_ue_communication_metadata *m2);

#endif
