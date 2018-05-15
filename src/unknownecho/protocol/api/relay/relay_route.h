#ifndef UNKNOWNECHO_ROUTE_H
#define UNKNOWNECHO_ROUTE_H

#include <unknownecho/protocol/api/relay/relay_route_struct.h>
#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <unknownecho/bool.h>

ue_relay_route *ue_relay_route_create(ue_relay_step **steps, int steps_number);

void ue_relay_route_destroy(ue_relay_route *route);

void ue_relay_route_destroy_all(ue_relay_route *route);

bool ue_relay_route_is_valid(ue_relay_route *route);

ue_relay_step *ue_relay_route_get_receiver(ue_relay_route *route);

ue_relay_step *ue_relay_route_get_sender(ue_relay_route *route);

#endif
