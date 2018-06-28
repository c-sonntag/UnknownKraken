#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

ue_relay_route *ue_relay_route_create(ue_relay_step **steps, int steps_number) {
    ue_relay_route *route;

    ueum_safe_alloc(route, ue_relay_route, 1);
    route->steps = steps;
    route->steps_number = steps_number;

    return route;
}

ue_relay_route *ue_relay_route_create_back_route(ue_relay_route *route) {
    ue_relay_route *back_route;
    int i, j;

    ueum_safe_alloc(back_route, ue_relay_route, 1);
    back_route->steps_number = route->steps_number;
    ueum_safe_alloc(back_route->steps, ue_relay_step *, back_route->steps_number);

    for (i = route->steps_number - 1, j = 0; i >= 0; i--, j++) {
        back_route->steps[j] = ue_relay_step_create_from_step(route->steps[i]);
    }

    return back_route;
}

void ue_relay_route_destroy(ue_relay_route *route) {
    int i;

    if (route) {
        if (route->steps) {
            for (i = 0; i < route->steps_number; i++) {
                ue_relay_step_destroy(route->steps[i]);
            }
            ueum_safe_free(route->steps);
        }
        ueum_safe_free(route);
    }
}

void ue_relay_route_destroy_all(ue_relay_route *route) {
    int i;

    if (route) {
        if (route->steps) {
            for (i = 0; i < route->steps_number; i++) {
                ue_relay_step_destroy_all(route->steps[i]);
            }
            ueum_safe_free(route->steps);
        }
        ueum_safe_free(route);
    }
}

bool ue_relay_route_is_valid(ue_relay_route *route) {
    int i;

    if (!route) {
        ei_stacktrace_push_msg("Specified route ptr is null");
        return false;
    }

    if (!route->steps || route->steps_number <= 0) {
        ei_stacktrace_push_msg("Specified route steps is null");
        return false;
    }

    for (i = 0; i < route->steps_number; i++) {
        if (!ue_relay_step_is_valid(route->steps[i])) {
            ei_stacktrace_push_msg("Step at iteration %d is invalid", i);
            return false;
        }
    }

    if (!ue_relay_step_get_our_crypto_metadata(ue_relay_route_get_sender(route))) {
        ei_stacktrace_push_msg("Sender step doesn't provide our crypto metadata");
        return false;
    }

    return true;
}

ue_relay_step *ue_relay_route_get_receiver(ue_relay_route *route) {
    if (!route) {
        ei_stacktrace_push_msg("Specified route ptr is null");
        return NULL;
    }

    if (!route->steps || route->steps_number <= 0) {
        ei_stacktrace_push_msg("Specified route steps is null");
        return NULL;
    }

    return route->steps[route->steps_number - 1];
}

ue_relay_step *ue_relay_route_get_sender(ue_relay_route *route) {
    if (!route) {
        ei_stacktrace_push_msg("Specified route ptr is null");
        return NULL;
    }

    if (!route->steps || route->steps_number <= 0) {
        ei_stacktrace_push_msg("Specified route steps is null");
        return NULL;
    }

    return route->steps[0];
}

bool ue_relay_route_print(ue_relay_route *route, FILE *fd) {
    int i;

    if (!route) {
        ei_stacktrace_push_msg("Specified route ptr is null");
        return false;
    }

    if (!route->steps || route->steps_number <= 0) {
        ei_stacktrace_push_msg("Specified route steps is null");
        return false;
    }

    for (i = 0; i < route->steps_number; i++) {
        printf("#%d ", i + 1);
        ue_relay_step_print(route->steps[i], fd);
    }

    return true;
}
