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

#include <ueum/ueum.h>

#include <ei/ei.h>

#if defined(_WIN32)

#include <Windows.h>

#endif

/**
 * @todo add unix version
 * @todo check if there is an error in Windows XP as it doesn't return ERROR_INSUFFICIENT_BUFFER
 */
char *ueum_get_current_process_name() {
#if defined(_WIN32)
    char *szFileName, *error_buffer;

    ueum_safe_alloc(szFileName, char, MAX_PATH + 1);

    if (GetModuleFileNameA(NULL, szFileName, MAX_PATH + 1) == ERROR_INSUFFICIENT_BUFFER) {
        ei_get_last_werror(error_buffer);
        ei_stacktrace_push_msg("GetModuleFileNameA failed error message: %s", error_buffer);
        ueum_safe_free(szFileName);
        return NULL;
    }

    return szFileName;
#endif

    ei_stacktrace_push_msg("Unsupported OS");
    return NULL;
}
