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

#include <uk/utils/ei.h>

#include <stdlib.h>

int main() {
    uk_utils_init_or_die();

    uk_utils_logger_trace("Loading library...");

    uk_utils_logger_debug("Variable value is %d", 58);

    uk_utils_logger_info("User %s is now connected", "username");

    uk_utils_logger_warn("Loading time is consequently longer");

    uk_utils_logger_error("Invalid password");

    uk_utils_logger_fatal("Out of memory");

    uk_utils_uninit();

    return EXIT_SUCCESS;
}
