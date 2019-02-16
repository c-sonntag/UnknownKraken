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

#include <ueum/time/sleep.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <unistd.h>
    #include <time.h>
#endif

int ueum_millisleep(unsigned ms) {
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
