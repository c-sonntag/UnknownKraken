#include <unknownecho/init.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <ueum/ueum.h>

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
        //ue_relay_step_create(ue_communication_metadata_create_socket_type("B", "192.168.0.2", 5001), NULL, NULL),
        ue_relay_step_create(ue_communication_metadata_create_from_string("B:0:192.168.0.3:5001:0"), NULL, NULL),
        ue_relay_step_create(ue_communication_metadata_create_socket_type("C", "192.168.0.3", 5002), NULL, NULL)
    );

    for (i = 0; i < step_number; i++) {
        ue_relay_step_print(steps[i], stdout);
        ue_relay_step_destroy(steps[i]);
    }

    ueum_safe_free(steps);
    ue_uninit();

    return 0;
}
