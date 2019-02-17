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

#include <uk/utils/console/console.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <sys/ioctl.h>
#endif

#include <stdio.h>

int uk_utils_console_get_width() {
    int width;

#if defined(_WIN32) || defined(_WIN64)
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        width = csbi.srWindow.Right - csbi.srWindow.Left;
#else
        struct winsize win;
        ioctl(0, TIOCGWINSZ, &win);
        width = win.ws_col;
#endif

    return width;
}

void uk_utils_console_erase_previous_line() {
    printf("\033[A\033[2K");
}

void uk_utils_console_erase_previous_lines(int n) {
    int i;

    for (i = 0; i < n; i++) {
        uk_utils_console_erase_previous_line();
    }

    rewind(stdout);
}
