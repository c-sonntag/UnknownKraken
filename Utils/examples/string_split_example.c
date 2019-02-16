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
    const char *string, *delimiter;
    ueum_string_vector *vector;

    ei_init_or_die();
    ei_logger_use_symbol_levels();
    
    string = "oneUEtwoUEtree";
    delimiter = "UE";

    ei_logger_info("Splitting string '%s' with delimiter '%s'...", string, delimiter);
    if ((vector = ueum_string_split(string, delimiter)) == NULL) {
        ei_stacktrace_push_msg("Failed to split string");
        goto clean_up;
    }

    ei_logger_info("Split output:");
    ueum_string_vector_print(vector, stdout);

clean_up:
    ueum_string_vector_destroy(vector);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    ei_uninit();
    return 0;
}
