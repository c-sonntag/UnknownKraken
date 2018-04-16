#ifndef UNKNOWNECHO_RELAY_ROUTE_STRUCT_H
#define UNKNOWNECHO_RELAY_ROUTE_STRUCT_H

#include <unknownecho/protocol/api/relay/relay_point_struct.h>
#include <unknownecho/crypto/api/key/public_key.h>

typedef struct {
    ue_relay_point **points;
    int point_number;
    ue_public_key *final_public_key;
    const char *cipher_name;
    const char *digest_name;
} ue_relay_route;

#endif
