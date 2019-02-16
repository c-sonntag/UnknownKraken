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

void test_1() {
    ueum_progress_bar *progress_bar;
    int n, i;

    n = 100;
    progress_bar = ueum_progress_bar_create(n, "Loading", stdout);
    ueum_progress_bar_set_style(progress_bar, "#", "-");
    ueum_progress_bar_set_left_delimiter(progress_bar, "|");
    ueum_progress_bar_set_right_delimiter(progress_bar, "|");

    for (i = 0; i <= n; i++) {
        ueum_progress_bar_update_and_print(progress_bar, i);
        ueum_millisleep(10);
    }
    printf("\n");

    ueum_progress_bar_destroy(progress_bar);
}

void test_2() {
    ueum_progress_bar *progress_bar;
    int n, i;

    n = 1000;
    progress_bar = ueum_progress_bar_create(n, "Loading", stdout);
    ueum_progress_bar_set_frequency_update(progress_bar, 15);

#ifdef _WIN32
    ueum_progress_bar_set_style(progress_bar, "|", "-");
#else
    ueum_progress_bar_set_style(progress_bar, "\u2588", "-");
    ueum_progress_bar_set_colors(progress_bar, UNKNOWNECHOUTILSMODULE_COLOR_ID_ATTRIBUTE_DIM, -1,
    UNKNOWNECHOUTILSMODULE_COLOR_ID_BACKGROUND_BLACK);
#endif

    for (i = 0; i <= n; i++) {
        ueum_progress_bar_update_and_print(progress_bar, i);
        ueum_millisleep(1);
    }
    printf("\n");

    ueum_progress_bar_destroy(progress_bar);
}

void test_3() {
    ueum_progress_bar *progress_bar;
    int n;

    n = 5;
    progress_bar = ueum_progress_bar_create(n, "Loading", stdout);

    ueum_progress_bar_update_and_print(progress_bar, 0);
    ueum_millisleep(200);
    ueum_progress_bar_update_and_print(progress_bar, 1);
    ueum_millisleep(200);
    ueum_progress_bar_update_and_print(progress_bar, 2);
    ueum_millisleep(200);
    ueum_progress_bar_update_and_print(progress_bar, 3);
    ueum_millisleep(200);
    ueum_progress_bar_update_and_print(progress_bar, 4);
    ueum_millisleep(200);
    ueum_progress_bar_update_and_print(progress_bar, 5);
    ueum_millisleep(200);
    printf("\n");

    ueum_progress_bar_destroy(progress_bar);
}

void test_4() {
    ueum_progress_bar *progress_bar;
    int n, i;

    n = 100;
    progress_bar = ueum_progress_bar_create(n, "Progress:", stdout);
    ueum_progress_bar_set_style(progress_bar, "#", ".");

    for (i = 0; i <= n; i++) {
        ueum_progress_bar_update_and_print(progress_bar, i);
        ueum_millisleep(10);
    }
    printf("\n");

    ueum_progress_bar_destroy(progress_bar);
}

int main() {
    ei_init_or_die();
    ei_logger_use_symbol_levels();

    test_1();

    test_2();

    test_3();

    test_4();

    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }

    ei_uninit();

    return 0;
}
