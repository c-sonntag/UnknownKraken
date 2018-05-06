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
#include <unknownecho/console/color.h>
#include <unknownecho/alloc.h>

#include <stdio.h>

int main() {
    char *colored;

    ue_init();

    colored = ue_colorize_string("colored mother fucker.", UNKNOWNECHO_COLOR_ID_ATTRIBUTE_BOLD,
        UNKNOWNECHO_COLOR_ID_FOREGROUND_RED, UNKNOWNECHO_COLOR_ID_BACKGROUND_CYNAN);
    printf("%s\n", colored);
    ue_safe_free(colored);

    ue_uninit();

    return 0;
}
