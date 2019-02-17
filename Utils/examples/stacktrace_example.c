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

bool foo(void *parameter) {
    if (!parameter) {
        uk_utils_stacktrace_push_msg("Specified parameter is invalid");
        return false;
    }

    return true;
}

bool bar(void *parameter) {
    if (!foo(parameter)) {
        uk_utils_stacktrace_push_msg("foo failed :(");
        return false;
    }

    return true;
}

/**
 * output:
 * bar failed ! (thread 140171980306240)
 * Caused by: Specified parameter is invalid
 *    at foo (stacktrace_example.c:26)
 *    at bar (stacktrace_example.c:35)
 *    at main (stacktrace_example.c:58)
 */
int main() {
    void *arg;

    arg = NULL;

    uk_utils_init_or_die();

    if (!bar(arg)) {
        uk_utils_stacktrace_push_msg("bar failed !");
    }

    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_stacktrace_print();
    }

    uk_utils_uninit();

    return EXIT_SUCCESS;
}
