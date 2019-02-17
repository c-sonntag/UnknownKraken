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

#include <uk/utils/ueum.h> /* include LibUnknownEchoUtilsModule */
#include <uk/utils/ei.h> /* include LibErrorInterceptor */

int main() {
    char *data;

    uk_utils_init(); /* initialize LibErrorInterceptor */

    /* use LibUnknownEchoUtilsModule */

    /* return the content of the file */
    data = uk_utils_read_file("test.txt");

    /* free data only if it's allocated */
    uk_utils_safe_free(data);

    /**
     * If the file test.txt doesn't exist or cannot be
     * opened, libueum will used libei to record an error
     * in the stacktrace of the current thread.
     * If so, we can print the stacktrace.
     */
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_stacktrace_print_all();
    }

    uk_utils_uninit(); /* uninitialize LibErrorInterceptor */

    return 0;
}
