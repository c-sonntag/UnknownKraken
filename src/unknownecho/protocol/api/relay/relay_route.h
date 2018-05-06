#ifndef UNKNOWNECHO_ROUTE_H
#define UNKNOWNECHO_ROUTE_H

#include <unknownecho/protocol/api/relay/relay_route_struct.h>
#include <unknownecho/protocol/api/relay/relay_step_struct.h>

ue_relay_route *ue_relay_route_create(ue_relay_step **steps, int steps_number);

void ue_relay_route_destroy(ue_relay_route *route);

#endif
