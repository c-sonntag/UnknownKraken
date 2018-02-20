#ifndef UNKNOWNECHO_RELAY_POINT_H
#define UNKNOWNECHO_RELAY_POINT_H

#include <unknownecho/bool.h>

typedef struct {
    const char *host;
    int port;
} ue_relay_point;

ue_relay_point *ue_relay_point_create();

void ue_relay_point_destroy(ue_relay_point *relay_point);

bool ue_relay_point_set_host(ue_relay_point *relay_point, const char *host);

bool ue_relay_point_set_port(ue_relay_point *relay_point, int port);

#endif
