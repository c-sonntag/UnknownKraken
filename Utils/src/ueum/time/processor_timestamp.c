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

#include <ueum/time/processor_timestamp.h>

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

unsigned long long ueum_processor_timestamp() {
#if defined(__unix__)
    return rdtsc();
#elif defined(_WIN32)
    return processor_timestamp_windows();
#endif
}
