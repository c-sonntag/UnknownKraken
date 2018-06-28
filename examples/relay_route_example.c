#include <unknownecho/init.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>

#include <ei/ei.h>

#include <stdio.h>
#include <stdlib.h>

/**
 * @brief main
 * @todo print route
 * @todo replace route creation by a factory
 */
int main() {
    int step_number;
    ue_relay_route *route, *back_route;

    step_number = 2;
    route = NULL;
    back_route = NULL;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    /**
     * A: 192.168.0.1:5000
     * B: 192.168.0.2:5001
     * C: 192.168.0.3:5002
     * A -> B -> C
     * steps are represented by the arrows
     */
    route = ue_relay_route_create(
        ue_relay_steps_create(
            step_number,
            ue_relay_step_create(ue_communication_metadata_create_socket_type("B", "192.168.0.2", 5001), NULL, NULL),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("C", "192.168.0.3", 5002), NULL, NULL)
        ),
        step_number
    );

    ei_logger_info("Relay route:");
    ue_relay_route_print(route, stdout);

    ei_logger_info("Building back route from route...");
    back_route = ue_relay_route_create_back_route(route);

    ei_logger_info("Back relay route:");
    ue_relay_route_print(back_route, stdout);

    ue_relay_route_destroy(route);
    ue_relay_route_destroy(back_route);

    ue_uninit();

    return 0;
}
