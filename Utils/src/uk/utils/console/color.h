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

#ifndef UnknownKrakenUtils_COLOR_H
#define UnknownKrakenUtils_COLOR_H

#define UnknownKrakenUtils_COLOR_ID_ATTRIBUTE_RESET     0
#define UnknownKrakenUtils_COLOR_ID_ATTRIBUTE_BOLD      1
#define UnknownKrakenUtils_COLOR_ID_ATTRIBUTE_DIM       2
#define UnknownKrakenUtils_COLOR_ID_ATTRIBUTE_UNDERLINE 4
#define UnknownKrakenUtils_COLOR_ID_ATTRIBUTE_REVERSE   7
#define UnknownKrakenUtils_COLOR_ID_ATTRIBUTE_HIDDEN    8

#define UnknownKrakenUtils_COLOR_ID_FOREGROUND_BLACK   30
#define UnknownKrakenUtils_COLOR_ID_FOREGROUND_RED     31
#define UnknownKrakenUtils_COLOR_ID_FOREGROUND_GREEN   32
#define UnknownKrakenUtils_COLOR_ID_FOREGROUND_YELLOW  33
#define UnknownKrakenUtils_COLOR_ID_FOREGROUND_BLUE    34
#define UnknownKrakenUtils_COLOR_ID_FOREGROUND_MAGENTA 35
#define UnknownKrakenUtils_COLOR_ID_FOREGROUND_CYNAN   36
#define UnknownKrakenUtils_COLOR_ID_FOREGROUND_WHITE   37

#define UnknownKrakenUtils_COLOR_ID_BACKGROUND_BLACK   40
#define UnknownKrakenUtils_COLOR_ID_BACKGROUND_RED     41
#define UnknownKrakenUtils_COLOR_ID_BACKGROUND_GREEN   42
#define UnknownKrakenUtils_COLOR_ID_BACKGROUND_YELLOW  43
#define UnknownKrakenUtils_COLOR_ID_BACKGROUND_BLUE    44
#define UnknownKrakenUtils_COLOR_ID_BACKGROUND_MAGENTA 45
#define UnknownKrakenUtils_COLOR_ID_BACKGROUND_CYNAN   46
#define UnknownKrakenUtils_COLOR_ID_BACKGROUND_WHITE   47

#define UnknownKrakenUtils_COLOR_ESCAPE_RESET "\x1B[0m"

#define UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_BLACK   "\x1B[30m"
#define UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_RED     "\x1B[31m"
#define UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_GREEN   "\x1B[32m"
#define UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_YELLOW  "\x1B[33m"
#define UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_BLUE    "\x1B[34m"
#define UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_MAGENTA "\x1B[35m"
#define UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_CYNAN   "\x1B[36m"
#define UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_WHITE   "\x1B[37m"

#define UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_BLACK   "\x1B[40m"
#define UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_RED     "\x1B[41m"
#define UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_GREEN   "\x1B[42m"
#define UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_YELLOW  "\x1B[43m"
#define UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_BLUE    "\x1B[44m"
#define UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_MAGENTA "\x1B[45m"
#define UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_CYNAN   "\x1B[46m"
#define UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_WHITE   "\x1B[47m"

#define UnknownKrakenUtils_COLORIZE_FOREGROUND_RED(x) UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_RED x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_FOREGROUND_GREEN(x) UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_GREEN x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_FOREGROUND_YELLOW(x) UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_YELLOW x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_FOREGROUND_BLUE(x) UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_BLUE x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_FOREGROUND_MAGENTA(x) UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_MAGENTA x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_FOREGROUND_CYAN(x) UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_CYAN x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_FOREGROUND_WHITE(x) UnknownKrakenUtils_COLOR_ESCAPE_FOREGROUND_WHITE x UnknownKrakenUtils_COLOR_ESCAPE_RESET

#define UnknownKrakenUtils_COLORIZE_BACKGROUND_RED(x) UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_RED x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_BACKGROUND_GREEN(x) UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_GREEN x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_BACKGROUND_YELLOW(x) UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_YELLOW x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_BACKGROUND_BLUE(x) UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_BLUE x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_BACKGROUND_MAGENTA(x) UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_MAGENTA x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_BACKGROUND_CYAN(x) UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_CYAN x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_BACKGROUND_WHITE(x) UnknownKrakenUtils_COLOR_ESCAPE_BACKGROUND_WHITE x UnknownKrakenUtils_COLOR_ESCAPE_RESET

#define UnknownKrakenUtils_COLORIZE(x, color) color x UnknownKrakenUtils_COLOR_ESCAPE_RESET

#define UnknownKrakenUtils_COLORIZE_BOLD(x) "\x1B[1m" x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_DIM(x) "\x1B[2m" x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_UNDERLINE(x) "\x1B[4m" x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_REVERSE(x) "\x1B[7m" x UnknownKrakenUtils_COLOR_ESCAPE_RESET
#define UnknownKrakenUtils_COLORIZE_HIDDEN(x) "\x1B[8m" x UnknownKrakenUtils_COLOR_ESCAPE_RESET

char *uk_utils_colorize_string(const char *string, int attribute_id, int foreground_id, int background_id);

#endif
