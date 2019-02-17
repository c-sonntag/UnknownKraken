/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibSharedMemoryObject.                                 *
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

#include <uk/smo/smo.h>
#include <uk/smo/api/smo_handle.h>
#include <uk/smo/impl/windows/MemoryModule.h>

#include <uk/utils/ei.h>

uk_smo_handle *uk_smo_open(const char *id, unsigned char *data, size_t size) {
    uk_smo_handle *handle;
    void *object;
    char *error_buffer;

    uk_utils_check_parameter_or_return(id);
    uk_utils_check_parameter_or_return(data);
    uk_utils_check_parameter_or_return(size > 0);

    if (!(object = MemoryLoadLibrary(data, size))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to load library from memory with error message: '%s'", error_buffer);
        return NULL;
    }

    handle = uk_smo_handle_create(id);
    handle->object = object;

    return handle;
}

void *uk_smo_get_function(uk_smo_handle *handle, const char *function_name) {
    void *symbol;
    char *error_buffer;

    uk_utils_check_parameter_or_return(handle);
    uk_utils_check_parameter_or_return(function_name);
    
    if (!(symbol = MemoryGetProcAddress(handle->object, function_name))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to get symbol with error message: '%s'", error_buffer);
        return NULL;
    }

    return symbol;
}

bool uk_smo_close(uk_smo_handle *handle) {
    if (!handle) {
        uk_utils_logger_warn("smo handle already closed");
        return true;
    }

    MemoryFreeLibrary(handle->object);

    uk_smo_handle_destroy(handle);

    return true;
}
