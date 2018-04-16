#ifndef UNKNWOWNECHO_RELAY_POINT_H
#define UNKNWOWNECHO_RELAY_POINT_H

#include <unknownecho/protocol/api/relay/relay_point_struct.h>

ue_relay_point *ue_relay_point_create(const char *current_host, const char *next_host, const char *communication_type);

ue_relay_point **ue_relay_points_create(const char *communication_type, int *point_number, int host_number, ...);

void ue_relay_point_destroy(ue_relay_point *point);

#endif
