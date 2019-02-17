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

#include <uk/unknownecho/network/api/communication/communication_metadata.h>
#include <uk/unknownecho/defines.h>
#include <uk/utils/ei.h>
#include <uk/utils/ueum.h>

#include <stdio.h>
#include <string.h>

uk_ue_communication_metadata *uk_ue_communication_metadata_create_empty() {
    uk_ue_communication_metadata *metadata;

    metadata = NULL;

    uk_utils_safe_alloc(metadata, uk_ue_communication_metadata, 1);
    metadata->uid = NULL;
    metadata->host = NULL;
    metadata->port = 0;
    metadata->type = 0;
    metadata->destination_type = 0;

    return metadata;
}

uk_ue_communication_metadata *uk_ue_communication_metadata_create_from_string(const char *string) {
    uk_ue_communication_metadata *metadata;
    uk_utils_string_vector *vector;
    int elements_number;

    metadata = NULL;

    uk_utils_check_parameter_or_return(string);

    if (!(vector = uk_utils_string_split(string, ":"))) {
        uk_utils_stacktrace_push_msg("Failed to split strint metadata");
        return NULL;
    }

    if ((elements_number = uk_utils_string_vector_size(vector)) != 5) {
        uk_utils_stacktrace_push_msg("Input metadata string have an invalid number of arguments '%d'", elements_number);
        goto clean_up;
    }

    metadata = uk_ue_communication_metadata_create_empty();
    /* @todo fix memory leak here */
    uk_ue_communication_metadata_set_uid(metadata, uk_utils_string_create_from(uk_utils_string_vector_get(vector, 0)));
    uk_ue_communication_metadata_set_type(metadata, atoi(uk_utils_string_vector_get(vector, 1)));
    uk_ue_communication_metadata_set_host(metadata, uk_utils_string_create_from(uk_utils_string_vector_get(vector, 2)));
    uk_ue_communication_metadata_set_port(metadata, atoi(uk_utils_string_vector_get(vector, 3)));
    uk_ue_communication_metadata_set_destination_type(metadata, atoi(uk_utils_string_vector_get(vector, 4)));

clean_up:
    //uk_utils_string_vector_destroy(vector);
    return metadata;
}

void uk_ue_communication_metadata_destroy(uk_ue_communication_metadata *metadata) {
    if (metadata) {
        uk_utils_safe_free(metadata->host);
        uk_utils_safe_free(metadata);
    }
}

void uk_ue_communication_metadata_clean_up(uk_ue_communication_metadata *metadata) {
    if (metadata) {
        uk_utils_safe_free(metadata->host);
    }
}

uk_ue_communication_metadata *uk_ue_communication_metadata_copy(uk_ue_communication_metadata *metadata) {
    uk_ue_communication_metadata *copy;

    copy = uk_ue_communication_metadata_create_empty();
    copy->type = metadata->type;
    copy->uid = uk_utils_string_create_from(metadata->uid);
    if (metadata->type == UnknownKrakenUnknownEcho_COMMUNICATION_TYPE_SOCKET) {
        copy->host = uk_utils_string_create_from(metadata->host);
        copy->port = metadata->port;
    }
    copy->destination_type = metadata->destination_type;

    return copy;   
}

const char *uk_ue_communication_metadata_get_uid(uk_ue_communication_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->uid;
}

bool uk_ue_communication_metadata_set_uid(uk_ue_communication_metadata *metadata, const char *uid) {
    uk_utils_check_parameter_or_return(metadata);

    metadata->uid = uid;

    return true;
}

uk_ue_communication_type uk_ue_communication_metadata_get_type(uk_ue_communication_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->type;
}

bool uk_ue_communication_metadata_set_type(uk_ue_communication_metadata *metadata, uk_ue_communication_type type) {
    uk_utils_check_parameter_or_return(metadata);

    metadata->type = type;

    return true;
}

const char *uk_ue_communication_metadata_get_host(uk_ue_communication_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->host;
}

bool uk_ue_communication_metadata_set_host(uk_ue_communication_metadata *metadata, const char *host) {
   uk_utils_check_parameter_or_return(metadata);
   uk_utils_check_parameter_or_return(host);

   metadata->host = uk_utils_string_create_from(host);

   return true;
}

unsigned int uk_ue_communication_metadata_get_port(uk_ue_communication_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->port;
}

bool uk_ue_communication_metadata_set_port(uk_ue_communication_metadata *metadata, unsigned int port) {
    uk_utils_check_parameter_or_return(metadata);

    metadata->port = port;

    return true;
}

uk_ue_communication_destination_type uk_ue_communication_metadata_get_destination_type(uk_ue_communication_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->destination_type;
}

bool uk_ue_communication_metadata_set_destination_type(uk_ue_communication_metadata *metadata, uk_ue_communication_destination_type destination_type) {
    uk_utils_check_parameter_or_return(metadata);

    metadata->destination_type = destination_type;

    return true;
}

bool uk_ue_communication_metadata_is_valid(uk_ue_communication_metadata *metadata) {
    if (!metadata) {
        uk_utils_stacktrace_push_msg("Specified metadata ptr is null");
        return false;
    }

    if (!metadata->uid) {
        uk_utils_stacktrace_push_msg("Specified metadata object had a null uid");
        return false;
    }

    if (metadata->type != UnknownKrakenUnknownEcho_COMMUNICATION_TYPE_SOCKET) {
        uk_utils_stacktrace_push_msg("Only UnknownKrakenUnknownEcho_COMMUNICATION_TYPE_SOCKET is supported for now");
        return false;
    }

    if (metadata->destination_type != UnknownKrakenUnknownEcho_RELAY_SERVER &&
        metadata->destination_type != UnknownKrakenUnknownEcho_RELAY_CLIENT) {
        uk_utils_stacktrace_push_msg("Destination type '%d' is invalid", metadata->destination_type);
        return false;
    }

    if (metadata->type == UnknownKrakenUnknownEcho_COMMUNICATION_TYPE_SOCKET) {
        if (!metadata->host) {
            uk_utils_stacktrace_push_msg("The metadata type is of UnknownKrakenUnknownEcho_COMMUNICATION_SOCKET but no host is provide");
            return false;
        }
        if (metadata->port <= 0) {
            uk_utils_stacktrace_push_msg("The metadata type is of UnknownKrakenUnknownEcho_COMMUNICATION_SOCKET but the port is invalid");
            return false;
        }
    } else {
        uk_utils_stacktrace_push_msg("The type of communication of specified metadata is invalid");
        return false;
    }

    return true;
}

const char *uk_ue_communication_metadata_to_string(uk_ue_communication_metadata *metadata) {
    const char *string;

    if (!uk_ue_communication_metadata_is_valid(metadata)) {
        uk_utils_stacktrace_push_msg("Specified metadata object is invalid")
        return NULL;
    }

    if (metadata->type == UnknownKrakenUnknownEcho_COMMUNICATION_TYPE_SOCKET) {
        string = uk_utils_strcat_variadic("ssdsssdsd", uk_ue_communication_metadata_get_uid(metadata), ":",
            uk_ue_communication_metadata_get_type(metadata), ":",
            uk_ue_communication_metadata_get_host(metadata), ":",
            uk_ue_communication_metadata_get_port(metadata), ":",
            uk_ue_communication_metadata_get_destination_type(metadata));
    } else {
        uk_utils_stacktrace_push_msg("Unknown communication metadata type");
        return NULL;
    }

    return string;
}

bool uk_ue_communication_metadata_print(uk_ue_communication_metadata *metadata, FILE *fd) {
    const char *string;

    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(fd);

    string = uk_ue_communication_metadata_to_string(metadata);

    fprintf(fd, "%s", string);

    uk_utils_safe_free(string);

    return true;
}

bool uk_ue_communication_metadata_equals(uk_ue_communication_metadata *m1, uk_ue_communication_metadata *m2) {
    /**
     * @todo fix this issue
     */

    /*if (!uk_ue_communication_metadata_is_valid(m1)) {
        uk_utils_stacktrace_push_msg("First specified communication metadata ptr is invalid");
        return false;
    }

    if (!uk_ue_communication_metadata_is_valid(m2)) {
        uk_utils_stacktrace_push_msg("Second specified communication metadata ptr is invalid");
        return false;
    }*/

    if (!m1 || !m2 || !m1->uid || !m2->uid || !m1->type || !m2->type || !m1->host || !m2->host) {
        return false;
    }

    if (strcmp(m1->uid, m2->uid) == 0 &&
        m1->destination_type == m2->destination_type &&
        m1->type == m2->type && m1->type == UnknownKrakenUnknownEcho_COMMUNICATION_TYPE_SOCKET) {

        if (strcmp(m1->host, m2->host) == 0 && m1->port == m2->port) {
            return true;
        }
    }

    return false;
}
