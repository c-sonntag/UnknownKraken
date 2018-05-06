#include <unknownecho/init.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/alloc.h>

#include <stdio.h>
#include <stdlib.h>

int main() {
    int step_number, i;
    ue_relay_step **steps;

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
    steps = ue_relay_steps_create(
        step_number,
        ue_relay_step_create(ue_communication_metadata_create_socket_type("192.168.0.1", 5000),
            ue_communication_metadata_create_socket_type("192.168.0.2", 5001), NULL, NULL),
        ue_relay_step_create(ue_communication_metadata_create_socket_type("192.168.0.2", 5001),
            ue_communication_metadata_create_socket_type("192.168.0.3", 5002), NULL, NULL)
    );

    for (i = 0; i < step_number; i++) {
        ue_relay_step_print(steps[i], stdout);
        ue_relay_step_destroy(steps[i]);
    }

    ue_safe_free(steps);
    ue_uninit();

    return 0;
}
