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

#ifndef UNKNOWNECHO_COLOR_H
#define UNKNOWNECHO_COLOR_H

#define UNKNOWNECHO_COLOR_ID_ATTRIBUTE_RESET     0
#define UNKNOWNECHO_COLOR_ID_ATTRIBUTE_BOLD      1
#define UNKNOWNECHO_COLOR_ID_ATTRIBUTE_DIM       2
#define UNKNOWNECHO_COLOR_ID_ATTRIBUTE_UNDERLINE 4
#define UNKNOWNECHO_COLOR_ID_ATTRIBUTE_REVERSE   7
#define UNKNOWNECHO_COLOR_ID_ATTRIBUTE_HIDDEN    8

#define UNKNOWNECHO_COLOR_ID_FOREGROUND_BLACK   30
#define UNKNOWNECHO_COLOR_ID_FOREGROUND_RED     31
#define UNKNOWNECHO_COLOR_ID_FOREGROUND_GREEN   32
#define UNKNOWNECHO_COLOR_ID_FOREGROUND_YELLOW  33
#define UNKNOWNECHO_COLOR_ID_FOREGROUND_BLUE    34
#define UNKNOWNECHO_COLOR_ID_FOREGROUND_MAGENTA 35
#define UNKNOWNECHO_COLOR_ID_FOREGROUND_CYNAN   36
#define UNKNOWNECHO_COLOR_ID_FOREGROUND_WHITE   37

#define UNKNOWNECHO_COLOR_ID_BACKGROUND_BLACK   40
#define UNKNOWNECHO_COLOR_ID_BACKGROUND_RED     41
#define UNKNOWNECHO_COLOR_ID_BACKGROUND_GREEN   42
#define UNKNOWNECHO_COLOR_ID_BACKGROUND_YELLOW  43
#define UNKNOWNECHO_COLOR_ID_BACKGROUND_BLUE    44
#define UNKNOWNECHO_COLOR_ID_BACKGROUND_MAGENTA 45
#define UNKNOWNECHO_COLOR_ID_BACKGROUND_CYNAN   46
#define UNKNOWNECHO_COLOR_ID_BACKGROUND_WHITE   47

#define UNKNOWNECHO_COLOR_ESCAPE_RESET "\x1B[0m"

#define UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_BLACK   "\x1B[30m"
#define UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_RED     "\x1B[31m"
#define UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_GREEN   "\x1B[32m"
#define UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_YELLOW  "\x1B[33m"
#define UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_BLUE    "\x1B[34m"
#define UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_MAGENTA "\x1B[35m"
#define UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_CYNAN   "\x1B[36m"
#define UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_WHITE   "\x1B[37m"

#define UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_BLACK   "\x1B[40m"
#define UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_RED     "\x1B[41m"
#define UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_GREEN   "\x1B[42m"
#define UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_YELLOW  "\x1B[43m"
#define UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_BLUE    "\x1B[44m"
#define UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_MAGENTA "\x1B[45m"
#define UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_CYNAN   "\x1B[46m"
#define UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_WHITE   "\x1B[47m"

#define UNKNOWNECHO_COLORIZE_FOREGROUND_RED(x) UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_RED x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_FOREGROUND_GREEN(x) UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_GREEN x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_FOREGROUND_YELLOW(x) UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_YELLOW x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_FOREGROUND_BLUE(x) UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_BLUE x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_FOREGROUND_MAGENTA(x) UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_MAGENTA x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_FOREGROUND_CYAN(x) UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_CYAN x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_FOREGROUND_WHITE(x) UNKNOWNECHO_COLOR_ESCAPE_FOREGROUND_WHITE x UNKNOWNECHO_COLOR_ESCAPE_RESET

#define UNKNOWNECHO_COLORIZE_BACKGROUND_RED(x) UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_RED x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_BACKGROUND_GREEN(x) UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_GREEN x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_BACKGROUND_YELLOW(x) UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_YELLOW x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_BACKGROUND_BLUE(x) UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_BLUE x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_BACKGROUND_MAGENTA(x) UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_MAGENTA x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_BACKGROUND_CYAN(x) UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_CYAN x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_BACKGROUND_WHITE(x) UNKNOWNECHO_COLOR_ESCAPE_BACKGROUND_WHITE x UNKNOWNECHO_COLOR_ESCAPE_RESET

#define UNKNOWNECHO_COLORIZE(x, color) color x UNKNOWNECHO_COLOR_ESCAPE_RESET

#define UNKNOWNECHO_COLORIZE_BOLD(x) "\x1B[1m" x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_DIM(x) "\x1B[2m" x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_UNDERLINE(x) "\x1B[4m" x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_REVERSE(x) "\x1B[7m" x UNKNOWNECHO_COLOR_ESCAPE_RESET
#define UNKNOWNECHO_COLORIZE_HIDDEN(x) "\x1B[8m" x UNKNOWNECHO_COLOR_ESCAPE_RESET

char *ue_colorize_string(const char *string, int attribute_id, int foreground_id, int background_id);

#endif
