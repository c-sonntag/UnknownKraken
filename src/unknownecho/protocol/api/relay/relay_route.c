#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/errorHandling/stacktrace.h>
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

bool ue_relay_route_is_valid(ue_relay_route *route) {
    int i;

    if (!route) {
        ue_stacktrace_push_msg("Specified route ptr is null");
        return false;
    }

    if (!route->steps || route->steps_number <= 0) {
        ue_stacktrace_push_msg("Specified route steps is null");
        return false;
    }

    for (i = 0; i < route->steps_number; i++) {
        if (!ue_relay_step_is_valid(route->steps[i])) {
            ue_stacktrace_push_msg("Step at iteration %d is invalid", i);
            return false;
        }
    }

    if (!ue_relay_step_get_our_crypto_metadata(ue_relay_route_get_sender(route))) {
        ue_stacktrace_push_msg("Sender step doesn't provide our crypto metadata");
        return false;
    }

    return true;
}

ue_relay_step *ue_relay_route_get_receiver(ue_relay_route *route) {
    if (!route) {
        ue_stacktrace_push_msg("Specified route ptr is null");
        return NULL;
    }

    if (!route->steps || route->steps_number <= 0) {
        ue_stacktrace_push_msg("Specified route steps is null");
        return NULL;
    }

    return route->steps[route->steps_number - 1];
}

ue_relay_step *ue_relay_route_get_sender(ue_relay_route *route) {
    if (!route) {
        ue_stacktrace_push_msg("Specified route ptr is null");
        return NULL;
    }

    if (!route->steps || route->steps_number <= 0) {
        ue_stacktrace_push_msg("Specified route steps is null");
        return NULL;
    }

    return route->steps[0];
}
