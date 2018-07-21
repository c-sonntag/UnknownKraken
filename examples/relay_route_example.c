/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/init.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <ueum/ueum.h>
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
