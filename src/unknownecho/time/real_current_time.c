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

#include <unknownecho/time/real_current_time.h>
#include <unknownecho/time/current_time.h>
#include <ei/ei.h>

#include <time.h>

#if defined(__unix__)

#include <sys/time.h>

#elif defined(_WIN32) || defined(_WIN64)

#include <windows.h>

#endif

#if defined(_WIN32) || defined(_WIN64)

#define BILLION (1E9)
static BOOL g_first_time = 1;
static LARGE_INTEGER g_counts_per_sec;

int clock_gettime_windows(struct timespec *ct)
{
    LARGE_INTEGER count;

    if (g_first_time)
    {
        g_first_time = 0;

        if (0 == QueryPerformanceFrequency(&g_counts_per_sec))
        {
            g_counts_per_sec.QuadPart = 0;
        }
    }

    if ((NULL == ct) || (g_counts_per_sec.QuadPart <= 0) ||
            (0 == QueryPerformanceCounter(&count)))
    {
        return -1;
    }

    ct->tv_sec = count.QuadPart / g_counts_per_sec.QuadPart;
    ct->tv_nsec = ((count.QuadPart % g_counts_per_sec.QuadPart) * BILLION) / g_counts_per_sec.QuadPart;

    return 0;
}

#endif

/**
 * Source : https://stackoverflow.com/a/37920181
 */
unsigned long long ue_get_real_current_time() {
    //struct timespec ts = {0, 0};
    struct timeval tv;

    ei_logger_debug("Before");

/*#if defined(__unix__)
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
#elif defined(_WIN32) || defined(_WIN64)
    if (clock_gettime_windows(&ts) == 0) {
#endif
        printf("%ld\n", ts.tv_nsec);
        return (unsigned long long) (ts.tv_sec * 1000000 + ts.tv_nsec / 1000);
    } else */if (ue_time_of_day(&tv)) {
        return (unsigned long long) (tv.tv_sec * 1000000 + tv.tv_usec);
    }

    ei_logger_debug("After");

    ei_stacktrace_push_msg("Failed to get real current time or alternative");
    return 0;
}
