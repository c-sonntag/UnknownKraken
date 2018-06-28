#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/defines.h>
#include <ei/ei.h>
#include <ueum/ueum.h>

#include <stdio.h>
#include <string.h>

ue_communication_metadata *ue_communication_metadata_create_empty() {
    ue_communication_metadata *metadata;

    ueum_safe_alloc(metadata, ue_communication_metadata, 1);
    metadata->uid = NULL;
    metadata->host = NULL;
    metadata->port = 0;
    metadata->type = 0;
    metadata->destination_type = 0;

    return metadata;
}

ue_communication_metadata *ue_communication_metadata_create_from_string(const char *string) {
    ue_communication_metadata *metadata;
    ueum_string_vector *vector;
    int elements_number;

    metadata = NULL;

    ei_check_parameter_or_return(string);

    if (!(vector = ueum_string_split(string, ":"))) {
        ei_stacktrace_push_msg("Failed to split strint metadata");
        return NULL;
    }

    if ((elements_number = ueum_string_vector_size(vector)) != 5) {
        ei_stacktrace_push_msg("Input metadata string have an invalid number of arguments '%d'", elements_number);
        goto clean_up;
    }

    metadata = ue_communication_metadata_create_empty();
    /* @todo fix memory leak here */
    ue_communication_metadata_set_uid(metadata, ueum_string_create_from(ueum_string_vector_get(vector, 0)));
    ue_communication_metadata_set_type(metadata, atoi(ueum_string_vector_get(vector, 1)));
    ue_communication_metadata_set_host(metadata, ueum_string_create_from(ueum_string_vector_get(vector, 2)));
    ue_communication_metadata_set_port(metadata, atoi(ueum_string_vector_get(vector, 3)));
    ue_communication_metadata_set_destination_type(metadata, atoi(ueum_string_vector_get(vector, 4)));

clean_up:
    //ueum_string_vector_destroy(vector);
    return metadata;
}

void ue_communication_metadata_destroy(ue_communication_metadata *metadata) {
    if (metadata) {
        ueum_safe_free(metadata->host);
        ueum_safe_free(metadata);
    }
}

void ue_communication_metadata_clean_up(ue_communication_metadata *metadata) {
    if (metadata) {
        ueum_safe_free(metadata->host);
    }
}

ue_communication_metadata *ue_communication_metadata_copy(ue_communication_metadata *metadata) {
    ue_communication_metadata *copy;

    copy = ue_communication_metadata_create_empty();
    copy->type = metadata->type;
    copy->uid = ueum_string_create_from(metadata->uid);
    if (metadata->type == UNKNOWNECHO_COMMUNICATION_TYPE_SOCKET) {
        copy->host = ueum_string_create_from(metadata->host);
        copy->port = metadata->port;
    }
    copy->destination_type = metadata->destination_type;

    return copy;   
}

const char *ue_communication_metadata_get_uid(ue_communication_metadata *metadata) {
    ei_check_parameter_or_return(metadata);

    return metadata->uid;
}

bool ue_communication_metadata_set_uid(ue_communication_metadata *metadata, const char *uid) {
    ei_check_parameter_or_return(metadata);

    metadata->uid = uid;

    return true;
}

ue_communication_type ue_communication_metadata_get_type(ue_communication_metadata *metadata) {
    ei_check_parameter_or_return(metadata);

    return metadata->type;
}

bool ue_communication_metadata_set_type(ue_communication_metadata *metadata, ue_communication_type type) {
    ei_check_parameter_or_return(metadata);

    metadata->type = type;

    return true;
}

const char *ue_communication_metadata_get_host(ue_communication_metadata *metadata) {
    ei_check_parameter_or_return(metadata);

    return metadata->host;
}

bool ue_communication_metadata_set_host(ue_communication_metadata *metadata, const char *host) {
   ei_check_parameter_or_return(metadata);
   ei_check_parameter_or_return(host);

   metadata->host = ueum_string_create_from(host);

   return true;
}

unsigned int ue_communication_metadata_get_port(ue_communication_metadata *metadata) {
    ei_check_parameter_or_return(metadata);

    return metadata->port;
}

bool ue_communication_metadata_set_port(ue_communication_metadata *metadata, unsigned int port) {
    ei_check_parameter_or_return(metadata);

    metadata->port = port;

    return true;
}

ue_communication_destination_type ue_communication_metadata_get_destination_type(ue_communication_metadata *metadata) {
    ei_check_parameter_or_return(metadata);

    return metadata->destination_type;
}

bool ue_communication_metadata_set_destination_type(ue_communication_metadata *metadata, ue_communication_destination_type destination_type) {
    ei_check_parameter_or_return(metadata);

    metadata->destination_type = destination_type;

    return true;
}

bool ue_communication_metadata_is_valid(ue_communication_metadata *metadata) {
    if (!metadata) {
        ei_stacktrace_push_msg("Specified metadata ptr is null");
        return false;
    }

    if (!metadata->uid) {
        ei_stacktrace_push_msg("Specified metadata object had a null uid");
        return false;
    }

    if (metadata->type != UNKNOWNECHO_COMMUNICATION_TYPE_SOCKET) {
        ei_stacktrace_push_msg("Only UNKNOWNECHO_COMMUNICATION_TYPE_SOCKET is supported for now");
        return false;
    }

    if (metadata->destination_type != UNKNOWNECHO_RELAY_SERVER &&
        metadata->destination_type != UNKNOWNECHO_RELAY_CLIENT) {
        ei_stacktrace_push_msg("Destination type '%d' is invalid", metadata->destination_type);
        return false;
    }

    if (metadata->type == UNKNOWNECHO_COMMUNICATION_TYPE_SOCKET) {
        if (!metadata->host) {
            ei_stacktrace_push_msg("The metadata type is of UNKNOWNECHO_COMMUNICATION_SOCKET but no host is provide");
            return false;
        }
        if (metadata->port <= 0) {
            ei_stacktrace_push_msg("The metadata type is of UNKNOWNECHO_COMMUNICATION_SOCKET but the port is invalid");
            return false;
        }
    } else {
        ei_stacktrace_push_msg("The type of communication of specified metadata is invalid");
        return false;
    }

    return true;
}

const char *ue_communication_metadata_to_string(ue_communication_metadata *metadata) {
    const char *string;

    if (!ue_communication_metadata_is_valid(metadata)) {
        ei_stacktrace_push_msg("Specified metadata object is invalid")
        return NULL;
    }

    if (metadata->type == UNKNOWNECHO_COMMUNICATION_TYPE_SOCKET) {
        string = ueum_strcat_variadic("ssdsssdsd", ue_communication_metadata_get_uid(metadata), ":",
            ue_communication_metadata_get_type(metadata), ":",
            ue_communication_metadata_get_host(metadata), ":",
            ue_communication_metadata_get_port(metadata), ":",
            ue_communication_metadata_get_destination_type(metadata));
    } else {
        ei_stacktrace_push_msg("Unknown communication metadata type");
        return NULL;
    }

    return string;
}

bool ue_communication_metadata_print(ue_communication_metadata *metadata, FILE *fd) {
    const char *string;

    ei_check_parameter_or_return(metadata);
    ei_check_parameter_or_return(fd);

    string = ue_communication_metadata_to_string(metadata);

    fprintf(fd, "%s", string);

    ueum_safe_free(string);

    return true;
}

bool ue_communication_metadata_equals(ue_communication_metadata *m1, ue_communication_metadata *m2) {
    /**
     * @todo fix this issue
     */

    /*if (!ue_communication_metadata_is_valid(m1)) {
        ei_stacktrace_push_msg("First specified communication metadata ptr is invalid");
        return false;
    }

    if (!ue_communication_metadata_is_valid(m2)) {
        ei_stacktrace_push_msg("Second specified communication metadata ptr is invalid");
        return false;
    }*/

    if (!m1 || !m2 || !m1->uid || !m2->uid || !m1->type || !m2->type || !m1->host || !m2->host) {
        return false;
    }

    if (strcmp(m1->uid, m2->uid) == 0 &&
        m1->destination_type == m2->destination_type &&
        m1->type == m2->type && m1->type == UNKNOWNECHO_COMMUNICATION_TYPE_SOCKET) {

        if (strcmp(m1->host, m2->host) == 0 && m1->port == m2->port) {
            return true;
        }
    }

    return false;
}
