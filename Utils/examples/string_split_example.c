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

#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

int main() {
    const char *string, *delimiter;
    uk_utils_string_vector *vector;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();
    
    string = "oneUEtwoUEtree";
    delimiter = "UE";

    uk_utils_logger_info("Splitting string '%s' with delimiter '%s'...", string, delimiter);
    if ((vector = uk_utils_string_split(string, delimiter)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to split string");
        goto clean_up;
    }

    uk_utils_logger_info("Split output:");
    uk_utils_string_vector_print(vector, stdout);

clean_up:
    uk_utils_string_vector_destroy(vector);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return 0;
}
