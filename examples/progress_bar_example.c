/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/init.h>
#include <unknownecho/console/progress_bar.h>
#include <unknownecho/console/color.h>
#include <unknownecho/time/sleep.h>

#include <stdio.h>

void test_1() {
    ue_progress_bar *progress_bar;
    int n, i;

    n = 100;
    progress_bar = ue_progress_bar_create(n, "Loading", stdout);
    ue_progress_bar_set_style(progress_bar, "#", "-");
    ue_progress_bar_set_left_delimiter(progress_bar, "|");
    ue_progress_bar_set_right_delimiter(progress_bar, "|");

    for (i = 0; i <= n; i++) {
        ue_progress_bar_update_and_print(progress_bar, i);
        ue_millisleep(10);
    }
    printf("\n");

    ue_progress_bar_destroy(progress_bar);
}

void test_2() {
    ue_progress_bar *progress_bar;
    int n, i;

    n = 1000;
    progress_bar = ue_progress_bar_create(n, "Loading", stdout);

    ue_progress_bar_set_frequency_update(progress_bar, 15);
    ue_progress_bar_set_colors(progress_bar, UNKNOWNECHO_COLOR_ID_ATTRIBUTE_DIM, -1, UNKNOWNECHO_COLOR_ID_BACKGROUND_BLACK);

#ifdef _WINDOWS
    ue_progress_bar_set_style(progress_bar, "|", "-");
#else
    ue_progress_bar_set_style(progress_bar, "\u2588", "-");
#endif

    for (i = 0; i <= n; i++) {
        ue_progress_bar_update_and_print(progress_bar, i);
        ue_millisleep(1);
    }
    printf("\n");

    ue_progress_bar_destroy(progress_bar);
}

void test_3() {
    ue_progress_bar *progress_bar;
    int n;

    n = 5;
    progress_bar = ue_progress_bar_create(n, "Loading", stdout);

    ue_progress_bar_update_and_print(progress_bar, 0);
    ue_millisleep(200);
    ue_progress_bar_update_and_print(progress_bar, 1);
    ue_millisleep(200);
    ue_progress_bar_update_and_print(progress_bar, 2);
    ue_millisleep(200);
    ue_progress_bar_update_and_print(progress_bar, 3);
    ue_millisleep(200);
    ue_progress_bar_update_and_print(progress_bar, 4);
    ue_millisleep(200);
    ue_progress_bar_update_and_print(progress_bar, 5);
    ue_millisleep(200);
    printf("\n");

    ue_progress_bar_destroy(progress_bar);
}

void test_4() {
    ue_progress_bar *progress_bar;
    int n, i;

    n = 100;
    progress_bar = ue_progress_bar_create(n, "Progress:", stdout);
    ue_progress_bar_set_style(progress_bar, "#", ".");

    for (i = 0; i <= n; i++) {
        ue_progress_bar_update_and_print(progress_bar, i);
        ue_millisleep(10);
    }
    printf("\n");

    ue_progress_bar_destroy(progress_bar);
}

int main() {
    ue_init();

    //test_1();

    //test_2();

    //test_3();

    test_4();

    ue_uninit();

    return 0;
}
