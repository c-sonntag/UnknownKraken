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
    const char *file_name, *out_data;
    char *read_data;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    file_name = "hello.tmp";
    out_data = "hello";

    ei_logger_info("Check if file %s exists", file_name);
    if (ueum_is_file_exists(file_name)) {
        ei_logger_info("File %s already exist. Reading...", file_name);
        if ((read_data = ueum_read_file(file_name)) == NULL) {
            ei_stacktrace_push_msg("Failed to read file %s", file_name);
            goto clean_up;
        }
        ei_logger_info("The content of the file is: %s", read_data);
        ueum_safe_free(read_data);
    } else {
        ei_logger_info("File %s doesn't exist. Writing...", file_name);
        if (!ueum_write_file(file_name, out_data)) {
            ei_stacktrace_push_msg("Failed to write to file %s", file_name);
        }
    }

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    ei_uninit();
    return 0;
}
