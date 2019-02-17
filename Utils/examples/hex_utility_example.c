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
    unsigned char *bytes;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();    

    uk_utils_logger_info("Creating bytes from Hello world string...");
    if ((bytes = uk_utils_bytes_create_from_string("Hello world !")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create bytes from string");
        goto clean_up;
    }
    
    if (!uk_utils_hex_print(bytes, strlen("Hello world"), stdout)) {
        uk_utils_stacktrace_push_msg("Failed to print bytes to stdout");
        goto clean_up;
    }

    uk_utils_logger_info("Succeed !");

clean_up:
    uk_utils_safe_free(bytes);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return 0;
}
