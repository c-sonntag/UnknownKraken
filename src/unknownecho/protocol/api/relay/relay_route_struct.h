#ifndef UNKNOWNECHO_RELAY_ROUTE_STRUCT_H
#define UNKNOWNECHO_RELAY_ROUTE_STRUCT_H

#include <unknownecho/protocol/api/relay/relay_step_struct.h>

typedef struct {
    ue_relay_step **steps;
    int steps_number;
} ue_relay_route;

#endif
