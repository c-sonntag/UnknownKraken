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

#include <unknownecho/time/sleep.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <unistd.h>
    #include <time.h>
#endif

int ue_millisleep(unsigned ms) {
#if defined(_WIN32) || defined(_WIN64)
    SetLastError(0);
    Sleep(ms);
    return GetLastError() ? -1 : 0;

#elif _POSIX_C_SOURCE >= 199309L
    /* prefer to use nanosleep() */
    const struct timespec ts = {
        ms / 1000, /* seconds */
        (ms % 1000) * 1000 * 1000 /* nano seconds */
    };

    return nanosleep(&ts, NULL);

#elif _BSD_SOURCE || \
    (_XOPEN_SOURCE >= 500 || \
    _XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED) && \
    !(_POSIX_C_SOURCE >= 200809L || _XOPEN_SOURCE >= 700)

    /* else fallback to obsolte usleep() */
    return usleep(1000 * ms);

#else
    #error("No millisecond sleep available for this platform!")
    return -1;
#endif
}
