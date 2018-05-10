#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/string/string_split.h>
#include <unknownecho/container/string_vector.h>
#include <unknownecho/alloc.h>
#include <unknownecho/defines.h>

#include <stdio.h>
#include <string.h>

ue_communication_metadata *ue_communication_metadata_create_empty() {
    ue_communication_metadata *metadata;

    ue_safe_alloc(metadata, ue_communication_metadata, 1);
    metadata->host = NULL;
    metadata->port = 0;
    metadata->type = NULL;

    return metadata;
}

ue_communication_metadata *ue_communication_metadata_create_from_string(const char *string) {
    ue_communication_metadata *metadata;
    ue_string_vector *vector;
    int elements;

    metadata = NULL;

    ue_check_parameter_or_return(string);

    if (!(vector = ue_string_split((char *)string, ":"))) {
        ue_stacktrace_push_msg("Failed to split strint metadata");
        return NULL;
    }

    if ((elements = ue_string_vector_size(vector)) != 3) {
        ue_stacktrace_push_msg("Split string metadata doesn't contains 3 elements: %d", elements);
        goto clean_up;
    }

    metadata = ue_communication_metadata_create_empty();
    ue_communication_metadata_set_type(metadata, ue_string_vector_get(vector, 0));
    ue_communication_metadata_set_host(metadata, ue_string_vector_get(vector, 1));
    ue_communication_metadata_set_port(metadata, atoi(ue_string_vector_get(vector, 2)));

clean_up:
    ue_string_vector_destroy(vector);
    return metadata;
}

void ue_communication_metadata_destroy(ue_communication_metadata *metadata) {
    if (metadata) {
        ue_safe_free(metadata->host);
        ue_safe_free(metadata->type);
        ue_safe_free(metadata);
    }
}

void ue_communication_metadata_clean_up(ue_communication_metadata *metadata) {
    if (metadata) {
        ue_safe_free(metadata->host);
        ue_safe_free(metadata->type);
    }
}

const char *ue_communication_metadata_get_host(ue_communication_metadata *metadata) {
    ue_check_parameter_or_return(metadata);

    return metadata->host;
}

bool ue_communication_metadata_set_host(ue_communication_metadata *metadata, const char *host) {
   ue_check_parameter_or_return(metadata);
   ue_check_parameter_or_return(host);

   metadata->host = ue_string_create_from(host);

   return true;
}

unsigned int ue_communication_metadata_get_port(ue_communication_metadata *metadata) {
    ue_check_parameter_or_return(metadata);

    return metadata->port;
}

bool ue_communication_metadata_set_port(ue_communication_metadata *metadata, unsigned int port) {
    ue_check_parameter_or_return(metadata);
    ue_check_parameter_or_return(port > 0);

    metadata->port = port;

    return true;
}

const char *ue_communication_metadata_get_type(ue_communication_metadata *metadata) {
    ue_check_parameter_or_return(metadata);

    return metadata->type;
}

bool ue_communication_metadata_set_type(ue_communication_metadata *metadata, const char *type) {
    ue_check_parameter_or_return(metadata);
    ue_check_parameter_or_return(type);

    metadata->type = ue_string_create_from(type);

    return true;
}

bool ue_communication_metadata_is_valid(ue_communication_metadata *metadata) {
    if (!metadata) {
        ue_stacktrace_push_msg("Specified metadata ptr is null");
        return false;
    }

    if (!metadata->type) {
        ue_stacktrace_push_msg("Specified metadata has null type");
        return false;
    }

    if (strcmp(metadata->type, UNKNOWNECHO_COMMUNICATION_SOCKET) == 0) {
        if (!metadata->host) {
            ue_stacktrace_push_msg("The metadata type is of UNKNOWNECHO_COMMUNICATION_SOCKET but no host is provide");
            return false;
        }
        if (metadata->port <= 0) {
            ue_stacktrace_push_msg("The metadata type is of UNKNOWNECHO_COMMUNICATION_SOCKET but the port is invalid");
            return false;
        }
    } else {
        ue_stacktrace_push_msg("The type of communication of specified metadata is invalid");
        return false;
    }

    return true;
}

const char *ue_communication_metadata_to_string(ue_communication_metadata *metadata) {
    const char *string;

    ue_check_parameter_or_return(metadata);

    if (strcmp(metadata->type, UNKNOWNECHO_COMMUNICATION_SOCKET) == 0) {
        string = ue_strcat_variadic("ssssd", ue_communication_metadata_get_type(metadata), ":",
            ue_communication_metadata_get_host(metadata), ":",
            ue_communication_metadata_get_port(metadata));
    } else {
        ue_stacktrace_push_msg("Unknown communication metadata type");
        return NULL;
    }

    return string;
}

bool ue_communication_metadata_print(ue_communication_metadata *metadata, FILE *fd) {
    const char *string;

    ue_check_parameter_or_return(metadata);
    ue_check_parameter_or_return(fd);

    string = ue_communication_metadata_to_string(metadata);

    fprintf(fd, "%s", string);

    ue_safe_free(string);

    return true;
}

bool ue_communication_metadata_equals(ue_communication_metadata *m1, ue_communication_metadata *m2) {
    if (!ue_communication_metadata_is_valid(m1)) {
        ue_stacktrace_push_msg("First specified communication metadata ptr is invalid");
        return false;
    }

    if (!ue_communication_metadata_is_valid(m2)) {
        ue_stacktrace_push_msg("Second specified communication metadata ptr is invalid");
        return false;
    }

    if (strcmp(m1->type, m2->type) == 0 && strcmp(m1->type, UNKNOWNECHO_COMMUNICATION_SOCKET) == 0) {
        if (strcmp(m1->host, m2->host) == 0 && m1->port == m2->port) {
            return true;
        }
    }

    return false;
}
