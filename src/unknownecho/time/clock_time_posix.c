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

#include <unknownecho/time/clock_time_posix.h>

#include <time.h>
#include <sys/time.h>

/**
 * Source : https://stackoverflow.com/a/37920181
 */
unsigned long long ue_get_posix_clock_time() {
    struct timespec ts;
    struct timeval tv;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (unsigned long long) (ts.tv_sec * 1000000 + ts.tv_nsec / 1000);
    } else if (gettimeofday(&tv, NULL) == 0) {
        return (unsigned long long) (tv.tv_sec * 1000000 + tv.tv_usec);
    } else {
        return 0;
    }
}
