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
    char *password;

    password = NULL;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    uk_utils_logger_info("LibUnknownEchoUtilsModule is correctly initialized");
    
    if ((password = uk_utils_input_password("Enter a password: ", 32)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to get input password");
        goto clean_up;
    }

    uk_utils_logger_info("The password is: %s", password);

clean_up:
    uk_utils_safe_free(password);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return EXIT_SUCCESS;
}
