#include <unknownecho/init.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>

#include <stdio.h>
#include <stdlib.h>

/**
 * @brief main
 * @todo print route
 * @todo replace route creation by a factory
 */
int main() {
    int step_number;
    ue_relay_route *route;

    step_number = 2;

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
            ue_relay_step_create(ue_communication_metadata_create_socket_type("192.168.0.1", 5000),
                ue_communication_metadata_create_socket_type("192.168.0.2", 5001), NULL, NULL),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("192.168.0.2", 5001),
                ue_communication_metadata_create_socket_type("192.168.0.3", 5002), NULL, NULL)
        ),
        step_number
    );

    ue_relay_route_destroy(route);
    ue_uninit();

    return 0;
}
