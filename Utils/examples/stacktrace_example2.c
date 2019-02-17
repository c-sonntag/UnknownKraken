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

/**
 * output:
 * Oops ! (thread 140164974479168)
 *    at main (stacktrace_example2.c:33)
 */
int main() {
    uk_utils_init_or_die();

    uk_utils_stacktrace_push_msg("Oops !");

    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_stacktrace_print();
    }

    uk_utils_uninit();

    return EXIT_SUCCESS;
}
