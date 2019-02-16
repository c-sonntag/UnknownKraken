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

#ifndef UNKNOWNECHO_COMMUNICATION_METADATA_H
#define UNKNOWNECHO_COMMUNICATION_METADATA_H

#include <unknownecho/network/api/communication/communication_type.h>
#include <ueum/ueum.h>

#include <stdio.h>

typedef enum {
    UNKNOWNECHO_RELAY_SERVER,
    UNKNOWNECHO_RELAY_CLIENT
} ue_communication_destination_type;

typedef struct {
    const char *uid;
    ue_communication_type type;
    const char *host;
    unsigned int port;
    ue_communication_destination_type destination_type;
} ue_communication_metadata;

ue_communication_metadata *ue_communication_metadata_create_empty();

ue_communication_metadata *ue_communication_metadata_create_from_string(const char *string);

void ue_communication_metadata_destroy(ue_communication_metadata *metadata);

void ue_communication_metadata_clean_up(ue_communication_metadata *metadata);

ue_communication_metadata *ue_communication_metadata_copy(ue_communication_metadata *metadata);

const char *ue_communication_metadata_get_uid(ue_communication_metadata *metadata);

bool ue_communication_metadata_set_uid(ue_communication_metadata *metadata, const char *uid);

ue_communication_type ue_communication_metadata_get_type(ue_communication_metadata *metadata);

bool ue_communication_metadata_set_type(ue_communication_metadata *metadata, ue_communication_type type);

const char *ue_communication_metadata_get_host(ue_communication_metadata *metadata);

bool ue_communication_metadata_set_host(ue_communication_metadata *metadata, const char *host);

unsigned int ue_communication_metadata_get_port(ue_communication_metadata *metadata);

bool ue_communication_metadata_set_port(ue_communication_metadata *metadata, unsigned int port);

ue_communication_destination_type ue_communication_metadata_get_destination_type(ue_communication_metadata *metadata);

bool ue_communication_metadata_set_destination_type(ue_communication_metadata *metadata, ue_communication_destination_type destination_type);

bool ue_communication_metadata_is_valid(ue_communication_metadata *metadata);

const char *ue_communication_metadata_to_string(ue_communication_metadata *metadata);

bool ue_communication_metadata_print(ue_communication_metadata *metadata, FILE *fd);

bool ue_communication_metadata_equals(ue_communication_metadata *m1, ue_communication_metadata *m2);

#endif
