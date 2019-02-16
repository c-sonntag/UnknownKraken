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

#include <stdio.h>

int main() {
    char *colored;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    colored = ueum_colorize_string("Hello world !", UNKNOWNECHOUTILSMODULE_COLOR_ID_ATTRIBUTE_BOLD,
        UNKNOWNECHOUTILSMODULE_COLOR_ID_FOREGROUND_RED, UNKNOWNECHOUTILSMODULE_COLOR_ID_BACKGROUND_CYNAN);
    printf("%s\n", colored);
    ueum_safe_free(colored);

    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }

    ei_uninit();

    return 0;
}
