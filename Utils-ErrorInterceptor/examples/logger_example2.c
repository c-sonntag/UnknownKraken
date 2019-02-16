/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibErrorInterceptor.                                   *
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

#include <ei/ei.h>

#include <stdlib.h>

int main() {
    ei_init_or_die();

    ei_logger_use_symbol_levels();

    ei_logger_trace("Loading library...");

    ei_logger_debug("Variable value is %d", 58);

    ei_logger_info("User %s is now connected", "username");

    ei_logger_warn("Loading time is consequently longer");

    ei_logger_error("Invalid password");

    ei_logger_fatal("Out of memory");

    ei_uninit();

    return EXIT_SUCCESS;
}
