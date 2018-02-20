#include <unknownecho/protocol/relay_point.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/string/string_utility.h>

ue_relay_point *ue_relay_point_create() {
    ue_relay_point *relay_point;

    ue_safe_alloc(relay_point, ue_relay_point, 1);
    relay_point->host = NULL;
    relay_point->port = -1;

    return relay_point;
}

void ue_relay_point_destroy(ue_relay_point *relay_point) {
    if (relay_point) {
        ue_safe_free(relay_point->host);
        ue_safe_free(relay_point);
    }
}

bool ue_relay_point_set_host(ue_relay_point *relay_point, const char *host) {
    relay_point->host = ue_string_create_from(host);
    return true;
}

bool ue_relay_point_set_port(ue_relay_point *relay_point, int port) {
    relay_point->port = port;
    return true;
}
