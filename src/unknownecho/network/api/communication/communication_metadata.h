#ifndef UNKNOWNECHO_COMMUNICATION_METADATA_H
#define UNKNOWNECHO_COMMUNICATION_METADATA_H

#include <unknownecho/bool.h>

#include <stdio.h>

typedef enum {
    UNKNOWNECHO_RELAY_SERVER,
    UNKNOWNECHO_RELAY_CLIENT
} ue_communication_destination_type;

typedef struct {
    const char *host;
    unsigned int port;
    const char *type;
    ue_communication_destination_type destination_type;
} ue_communication_metadata;

ue_communication_metadata *ue_communication_metadata_create_empty();

ue_communication_metadata *ue_communication_metadata_create_from_string(const char *string);

void ue_communication_metadata_destroy(ue_communication_metadata *metadata);

void ue_communication_metadata_clean_up(ue_communication_metadata *metadata);

const char *ue_communication_metadata_get_host(ue_communication_metadata *metadata);

bool ue_communication_metadata_set_host(ue_communication_metadata *metadata, const char *host);

unsigned int ue_communication_metadata_get_port(ue_communication_metadata *metadata);

bool ue_communication_metadata_set_port(ue_communication_metadata *metadata, unsigned int port);

const char *ue_communication_metadata_get_type(ue_communication_metadata *metadata);

bool ue_communication_metadata_set_type(ue_communication_metadata *metadata, const char *type);

bool ue_communication_metadata_is_valid(ue_communication_metadata *metadata);

const char *ue_communication_metadata_to_string(ue_communication_metadata *metadata);

bool ue_communication_metadata_print(ue_communication_metadata *metadata, FILE *fd);

bool ue_communication_metadata_equals(ue_communication_metadata *m1, ue_communication_metadata *m2);

#endif
