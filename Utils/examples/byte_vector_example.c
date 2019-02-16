/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoUtilsModule.                             *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <ueum/ueum.h>
#include <ei/ei.h>

int main() {
    ueum_byte_vector *data;

    data = NULL;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    ei_logger_info("Creating an empty byte vector");
    if ((data = ueum_byte_vector_create_empty()) == NULL) {
        ei_stacktrace_push_msg("Failed to create empty byte vector data");
        goto clean_up;
    }

    ei_logger_info("Append hello world string");
    if (!ueum_byte_vector_append_string(data, "Hello world !")) {
        ei_stacktrace_push_msg("Failed to append string to byte vector data");
        goto clean_up;
    }

    ei_logger_info("Checking is byte vector is empty");
    if (ueum_byte_vector_is_empty(data)) {
        ei_stacktrace_push_msg("byte vector data is empty but it shouldn't")
        goto clean_up;
    }

    ei_logger_info("The byte vector isn't empty and contains %d element", ueum_byte_vector_size(data));

    ei_logger_info("The byte vector 'data' contains:");
    ueum_byte_vector_print(data, stdout);

clean_up:
    ueum_byte_vector_destroy(data);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    ei_uninit();
    return 0;
}
