#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/alloc.h>

ue_relay_route *ue_relay_route_create(ue_relay_step **steps, int steps_number) {
    ue_relay_route *route;

    ue_safe_alloc(route, ue_relay_route, 1);
    route->steps = steps;
    route->steps_number = steps_number;

    return route;
}

void ue_relay_route_destroy(ue_relay_route *route) {
    int i;

    if (route) {
        if (route->steps) {
            for (i = 0; i < route->steps_number; i++) {
                ue_relay_step_destroy(route->steps[i]);
            }
            ue_safe_free(route->steps);
        }
        ue_safe_free(route);
    }
}
