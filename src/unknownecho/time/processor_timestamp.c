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

#include <unknownecho/time/processor_timestamp.h>

/**
 * source : https://msdn.microsoft.com/en-us/library/twchhe95.aspx
 */
#if defined(__unix__)

/**
 * source : https://stackoverflow.com/questions/9887839/clock-cycle-count-wth-gcc
 */
#if defined(__i386__)
    static __inline__ unsigned long long rdtsc() {
        unsigned long long int x;
        __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
        return x;
    }
#elif defined(__x86_64__)
    static __inline__ unsigned long long rdtsc() {
        unsigned hi, lo;
        __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
        return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
    }
#endif

#elif defined(_WIN32) || defined(_WIN64)

#include <intrin.h>

static unsigned long long processor_timestamp_windows() {
    unsigned __int64 i;
    i = __rdtsc();
    return (unsigned long long)i;
}

#endif

unsigned long long ue_processor_timestamp() {
#if defined(__unix__)
    return rdtsc();
#elif defined(_WIN32)
    return processor_timestamp_windows();
#endif
}
