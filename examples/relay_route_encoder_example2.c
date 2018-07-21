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
#include <unknownecho/protocol/api/relay/relay_route_encoder.h>
#include <unknownecho/protocol/api/relay/relay_route_decoder.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <stdio.h>
#include <stdlib.h>

static bool extract_and_send_step(const char *step_id, const char *target_id, ue_relay_step **extracted_step,
    ueum_byte_stream *encoded_route, uecm_crypto_metadata *crypto_metadata) {

    ei_logger_info("Extracting step for %s...", step_id);
    if (!(*extracted_step = ue_relay_route_decode_pop_step(encoded_route, crypto_metadata))) {
        ei_stacktrace_push_msg("Failed to pop step from encoded route with B crypto metadata");
        return false;
    }
    ei_logger_info("Step for %s extracted: ", step_id);
    ue_relay_step_print(*extracted_step, stdout);

    ei_logger_info("Lets say %s send the remaining route to %s [...]", step_id, target_id);

    return true;
}

int main() {
    int step_number;
    ue_relay_route *route, *back_route;
    ueum_byte_stream *encoded_route, *encoded_back_route;
    uecm_crypto_metadata *our_crypto_metadata, *b_crypto_metadata, *c_crypto_metadata, *d_crypto_metadata;
    ue_relay_step *b_extracted_step, *c_extracted_step;

    step_number = 3;
    route = NULL;
    back_route = NULL;
    encoded_route = NULL;
    encoded_back_route = NULL;
    our_crypto_metadata = NULL;
    b_crypto_metadata = NULL;
    c_crypto_metadata = NULL;
    d_crypto_metadata = NULL;
    b_extracted_step = NULL;
    c_extracted_step = NULL;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ei_logger_info("LibUnknownEcho is correctly initialized");

    ei_logger_info("Generating crypto metadata for point A...");
    if (!(our_crypto_metadata = uecm_crypto_metadata_create_default())) {
        ei_stacktrace_push_msg("Failed to generate default crypto metadata for point A");
        goto clean_up;
    }

    ei_logger_info("Generating crypto metadata for point B...");
    if (!(b_crypto_metadata = uecm_crypto_metadata_create_default())) {
        ei_stacktrace_push_msg("Failed to generate default crypto metadata for point B");
        goto clean_up;
    }

    ei_logger_info("Generating crypto metadata for point C...");
    if (!(c_crypto_metadata = uecm_crypto_metadata_create_default())) {
        ei_stacktrace_push_msg("Failed to generate default crypto metadata for point C");
        goto clean_up;
    }

    ei_logger_info("Generating crypto metadata for point D...");
    if (!(d_crypto_metadata = uecm_crypto_metadata_create_default())) {
        ei_stacktrace_push_msg("Failed to generate default crypto metadata for point D");
        goto clean_up;
    }

    ei_logger_info("Creating route...");

    /**
     * A: 192.168.0.1
     * B: 192.168.0.2:5001
     * C: 192.168.0.3:5002
     * D: 0:192.168.0.4:5002:1
     * client1 (A) -> server1 (B) -> server2 (C) -> client2 (D)
     * steps are represented by the arrows
     */
    if (!(route = ue_relay_route_create(
        ue_relay_steps_create(
            step_number,
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server1", "192.168.0.2", 5001),
                our_crypto_metadata, b_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server2", "192.168.0.3", 5002),
                our_crypto_metadata, c_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_from_string("client2:0:192.168.0.4:5002:1"),
                our_crypto_metadata, d_crypto_metadata)
        ),
        step_number))) {

        ei_stacktrace_push_msg("Failed to create route A -> B -> C -> D");
        goto clean_up;
    }

    ei_logger_info("Creating back route...");

    /**
     * A: 192.168.0.1
     * B: 192.168.0.2:5001
     * C: 192.168.0.3:5002
     * D: 0:192.168.0.4:5002:1
     * client2 (D) -> server2 (C) -> server1 (B) -> client1 (D)
     * steps are represented by the arrows
     */
    if (!(back_route = ue_relay_route_create(
        ue_relay_steps_create(
            step_number,
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server2", "192.168.0.3", 5002),
                d_crypto_metadata, c_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server1", "192.168.0.2", 5001),
                d_crypto_metadata, b_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_from_string("client1:0:192.168.0.1:5001:1"),
                d_crypto_metadata, our_crypto_metadata)
        ),
        step_number))) {

        ei_stacktrace_push_msg("Failed to create back route D -> C -> B -> A");
        goto clean_up;
    }

    ei_logger_info("Encoding route...");
    if (!(encoded_route = ue_relay_route_encode(route))) {
        ei_stacktrace_push_msg("Failed to encode route A -> B -> C -> D");
        goto clean_up;
    }

    ei_logger_info("Encoded route:");
    ueum_byte_stream_print_hex(encoded_route, stdout);

    ei_logger_info("Encoding back route...");
    if (!(encoded_back_route = ue_relay_route_encode(back_route))) {
        ei_stacktrace_push_msg("Failed to encode back route D -> C -> B -> A");
        goto clean_up;
    }

    ei_logger_info("Encoded back route:");
    ueum_byte_stream_print_hex(encoded_back_route, stdout);

    extract_and_send_step("B", "C", &b_extracted_step, encoded_route, b_crypto_metadata);

    extract_and_send_step("C", "D", &c_extracted_step, encoded_route, c_crypto_metadata);

    ei_logger_info("No more step to extract, as D is the end point");

    ei_logger_info("Executing the back route...");

    ue_relay_step_destroy(b_extracted_step);
    ue_relay_step_destroy(c_extracted_step);

    extract_and_send_step("C", "B", &c_extracted_step, encoded_back_route, c_crypto_metadata);

    extract_and_send_step("B", "A", &b_extracted_step, encoded_back_route, b_crypto_metadata);

    ei_logger_info("No more step to extract, as A is the end point");

clean_up:
    ueum_byte_stream_destroy(encoded_route);
    ueum_byte_stream_destroy(encoded_back_route);
    ue_relay_route_destroy(route);
    ue_relay_route_destroy(back_route);
    uecm_crypto_metadata_destroy_all(our_crypto_metadata);
    uecm_crypto_metadata_destroy_all(b_crypto_metadata);
    uecm_crypto_metadata_destroy_all(c_crypto_metadata);
    uecm_crypto_metadata_destroy_all(d_crypto_metadata);
    ue_relay_step_destroy(b_extracted_step);
    ue_relay_step_destroy(c_extracted_step);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
