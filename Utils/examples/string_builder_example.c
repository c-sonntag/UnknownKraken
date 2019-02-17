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

#include <string.h>

int main() {
    uk_utils_string_builder *builder;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();
    
    uk_utils_logger_info("Creating string builder...");
    if ((builder = uk_utils_string_builder_create()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create new string builder");
        goto clean_up;
    }

    uk_utils_logger_info("Append string to builder...");
    if (!uk_utils_string_builder_append(builder, "Hello world !", strlen("Hello world !"))) {
        uk_utils_stacktrace_push_msg("Failed to append string to builder");
        goto clean_up;
    }

    uk_utils_logger_info("The string builder contains %ld chars with data: %s",
        uk_utils_string_builder_get_position(builder),
        uk_utils_string_builder_get_data(builder)
    );

clean_up:
    uk_utils_string_builder_destroy(builder);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return 0;
}
