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

#include <stdio.h>

int main() {
    char *colored;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    colored = uk_utils_colorize_string("Hello world !", UnknownKrakenUtils_COLOR_ID_ATTRIBUTE_BOLD,
        UnknownKrakenUtils_COLOR_ID_FOREGROUND_RED, UnknownKrakenUtils_COLOR_ID_BACKGROUND_CYNAN);
    printf("%s\n", colored);
    uk_utils_safe_free(colored);

    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }

    uk_utils_uninit();

    return 0;
}
