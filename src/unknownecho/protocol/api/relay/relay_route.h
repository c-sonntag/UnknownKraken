#ifndef UNKNOWNECHO_ROUTE_H
#define UNKNOWNECHO_ROUTE_H

#include <unknownecho/protocol/api/relay/relay_route_struct.h>

ue_relay_route *ue_relay_route_create(ue_relay_point **points, int point_number, ue_public_key *final_public_key ,const char *cipher_name,
    const char *digest_name);

void ue_relay_route_destroy(ue_relay_route *route);

#endif
