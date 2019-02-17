/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibMemorySlot.                                         *
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

#include <uk/ms/impl/win/resource.h>

#include <uk/utils/ei.h>

#include <Windows.h>
#include <string.h>

typedef struct {
    int id;
    bool found;
} resource_name_search_ctx;

typedef struct {
    bool searching;
    unsigned char *searched_data;
    size_t searched_data_size;
    int found_id;
} resource_data_search_ctx;

typedef struct {
    int *ids;
    int number;
} resource_id_search_ctx;

static unsigned char *resource_load_internal(HMODULE hLibrary, int id, size_t *size) {
    unsigned char *data, *loaded_data;
    HRSRC hResource;
    HGLOBAL hResourceLoaded;
    char *error_buffer;

    uk_utils_check_parameter_or_return(hLibrary);
    uk_utils_check_parameter_or_return(id > 0);

    data = NULL;
    loaded_data = NULL;
    hResource = NULL;
    hResourceLoaded = NULL;
    error_buffer = NULL;

    if (!(hResource = FindResourceA(hLibrary, MAKEINTRESOURCE(id), RT_RCDATA))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to find resource with error message: '%s'", error_buffer);
        return NULL;
    }

    if (!(hResourceLoaded = LoadResource(hLibrary, hResource))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to load resource with error message: '%s'", error_buffer);
        return NULL;
    }

    if (!(loaded_data = (LPBYTE)LockResource(hResourceLoaded))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to lock resource with error message: '%s'", error_buffer);
        return NULL;
    }

    *size = SizeofResource(hLibrary, hResource);

    uk_utils_safe_alloc(data, unsigned char, *size);
    memcpy(data, loaded_data, *size * sizeof(unsigned char));
    
    return data;
}

BOOL CALLBACK ResNameProc(HANDLE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG lParam) {
    resource_name_search_ctx *ctx;
    char *resource_name;

    ctx = (resource_name_search_ctx *)lParam;
    resource_name = NULL;

    if (!IS_INTRESOURCE(lpszName)) {
        uk_utils_stacktrace_push_msg("Resource id isn't an integer");
        return FALSE;
    }

    uk_utils_safe_alloc(resource_name, char, 3);
    wsprintf(resource_name, "%d", (USHORT)lpszName);
    ctx->found = atoi(resource_name) == ctx->id;
    uk_utils_safe_free(resource_name);

    return TRUE;
}

BOOL CALLBACK ResDataProc(HANDLE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG lParam) {
    resource_data_search_ctx *ctx;
    char *resource_name;
    int current_id;
    unsigned char *current_data;
    size_t current_data_size;

    ctx = (resource_data_search_ctx *)lParam;
    resource_name = NULL;

    if (!ctx->searching) {
        return TRUE;
    }

    if (!IS_INTRESOURCE(lpszName)) {
        uk_utils_stacktrace_push_msg("Resource id isn't an integer");
        return FALSE;
    }

    uk_utils_safe_alloc(resource_name, char, 3);
    wsprintf(resource_name, "%d", (USHORT)lpszName);
    current_id = atoi(resource_name);

    if (!(current_data = resource_load_internal(hModule, current_id, &current_data_size))) {
        uk_utils_stacktrace_push_msg("Failed to load current resource with id %d", current_id);
        uk_utils_safe_free(resource_name);
        return FALSE;
    }

    if (ctx->searched_data_size != current_data_size) {
        uk_utils_logger_debug("Size doesn't matched ; skipping");
        uk_utils_safe_free(resource_name);
        return TRUE;
    }

    if (memcmp(ctx->searched_data, current_data, ctx->searched_data_size) != 0) {
        uk_utils_logger_debug("Size are equals but data doesn't matched ; skipping");
        uk_utils_safe_free(resource_name);
        return TRUE;
    }

    ctx->searching = false;
    ctx->found_id = current_id;

    uk_utils_safe_free(resource_name);

    return TRUE;
}

BOOL CALLBACK ResIdProc(HANDLE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG lParam) {
    resource_id_search_ctx *ctx;
    char *resource_name;

    ctx = (resource_id_search_ctx *)lParam;
    resource_name = NULL;

    if (!IS_INTRESOURCE(lpszName)) {
        uk_utils_stacktrace_push_msg("Resource id isn't an integer");
        return FALSE;
    }

    uk_utils_safe_alloc(resource_name, char, 3);
    wsprintf(resource_name, "%d", (USHORT)lpszName);
    if (!ctx->ids) {
        uk_utils_safe_alloc(ctx->ids, int, 1);
    }
    else {
        uk_utils_safe_realloc(ctx->ids, int, ctx->number, 1);
    }
    ctx->ids[ctx->number] = atoi(resource_name);
    ctx->number++;
    uk_utils_safe_free(resource_name);
    
    return TRUE;
}

unsigned char *uk_ms_resource_load_from_path(const char *target_path, int id, size_t *size) {
    unsigned char *data;
    HMODULE hLibrary;
    char *error_buffer;

    uk_utils_check_parameter_or_return(target_path);
    uk_utils_check_parameter_or_return(id > 0);

    data = NULL;
    error_buffer = NULL;

    if (!uk_utils_is_file_exists(target_path)) {
        uk_utils_stacktrace_push_msg("Specified target path doesn't exist");
        return NULL;
    }
    
    if (!(hLibrary = LoadLibraryA(target_path))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("LoadLibraryA failed with error message: '%s'", error_buffer);
        return NULL;
    }
    
    if (!(data = resource_load_internal(hLibrary, id, size))) {
        uk_utils_stacktrace_push_msg("Failed to load resource");
        FreeLibrary(hLibrary);
        return NULL;
    }

    FreeLibrary(hLibrary);

    return data;
}

unsigned char *uk_ms_resource_load_from_memory(int id, size_t *size) {
    unsigned char *data;
    HMODULE hLibrary;
    char *error_buffer;
    size_t teuk_mp_size;

    uk_utils_check_parameter_or_return(id > 0);

    data = NULL;
    error_buffer = NULL;
    *size = 0;

    if (!(hLibrary = GetModuleHandle(NULL))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to get our module handle with error message: '%s'", error_buffer);
        return NULL;
    }

    if (!(data = resource_load_internal(hLibrary, id, &teuk_mp_size))) {
        uk_utils_stacktrace_push_msg("Failed to load resource");
        FreeLibrary(hLibrary);
        return NULL;
    }

    *size = teuk_mp_size;

    FreeLibrary(hLibrary);

    return data;
}

bool uk_ms_resource_save(const char *target_path, unsigned char *data, size_t size, int id) {
    bool result;
    HANDLE hResource;
    char *error_buffer;

    uk_utils_check_parameter_or_return(target_path);
    uk_utils_check_parameter_or_return(data);
    uk_utils_check_parameter_or_return(size > 0);
    uk_utils_check_parameter_or_return(id > 0);

    result = false;
    hResource = NULL;
    error_buffer = NULL;

    if (!(hResource = BeginUpdateResourceA(target_path, FALSE))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("BeginUpdateResourceA failed with error message: '%s'", error_buffer);
        goto clean_up;
    }

    if (UpdateResourceA(hResource,
        RT_RCDATA,
        MAKEINTRESOURCE(id),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPVOID)data,
        size) == FALSE) {

        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("UpdateResourceA failed with error message: '%s'", error_buffer);
        goto clean_up;
    }

    if (EndUpdateResourceA(hResource, FALSE) == FALSE) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("EndUpdateResourceA failed with error message: '%s'", error_buffer);
        goto clean_up;
    }

    result = true;

clean_up:
    CloseHandle(hResource);
    return result;
}

bool uk_ms_resource_exist(const char *target_path, int id) {
    HANDLE hResource;
    resource_name_search_ctx ctx;
    char *error_buffer;

    ctx.id = id;
    ctx.found = false;

    if (!(hResource = LoadLibraryA(target_path))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to load library with error message: %s", error_buffer);
        return false;
    }

    if (!EnumResourceNames(hResource, RT_RCDATA, (ENUMRESNAMEPROC)ResNameProc, (LONG_PTR)&ctx)) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to enum resource names with error message: %s", error_buffer);
        FreeLibrary(hResource);
        return false;
    }

    FreeLibrary(hResource);

    return ctx.found;
}

int uk_ms_resource_find_id_from_path(const char *target_path, unsigned char *data, size_t size) {
    int id;
    HMODULE hLibrary;
    char *error_buffer;
    resource_data_search_ctx ctx;

    if (!target_path) {
        uk_utils_stacktrace_push_msg("Specified target_path ptr is null");
        return -1;
    }

    if (!data) {
        uk_utils_stacktrace_push_msg("Specified data ptr is null");
        return -1;
    }

    if (size == 0) {
        uk_utils_stacktrace_push_msg("Specified size is invalid");
        return -1;
    }

    if (!uk_utils_is_file_exists(target_path)) {
        uk_utils_stacktrace_push_msg("Specified target path doesn't exist");
        return -1;
    }

    if (!(hLibrary = LoadLibraryA(target_path))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("LoadLibraryA failed with error message: '%s'", error_buffer);
        return -1;
    }

    ctx.searching = true;
    ctx.found_id = -1;
    ctx.searched_data = data;
    ctx.searched_data_size = size;

    if (!EnumResourceNames(hLibrary, RT_RCDATA, (ENUMRESNAMEPROC)ResDataProc, (LONG_PTR)&ctx)) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to enum resource names with error message: %s", error_buffer);
        FreeLibrary(hLibrary);
        return -1;
    }

    FreeLibrary(hLibrary);

    return ctx.found_id;
}

int uk_ms_resource_find_id_from_memory(unsigned char *data, size_t size) {
    int id;
    HMODULE hLibrary;
    char *error_buffer;
    resource_data_search_ctx ctx;

    if (!data) {
        uk_utils_stacktrace_push_msg("Specified data ptr is null");
        return -1;
    }

    if (size == 0) {
        uk_utils_stacktrace_push_msg("Specified size is invalid");
        return -1;
    }

    if (!(hLibrary = GetModuleHandle(NULL))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to get our module handle with error message: '%s'", error_buffer);
        return -1;
    }

    ctx.searching = true;
    ctx.found_id = -1;
    ctx.searched_data = data;
    ctx.searched_data_size = size;

    if (!EnumResourceNames(hLibrary, RT_RCDATA, (ENUMRESNAMEPROC)ResDataProc, (LONG_PTR)&ctx)) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to enum resource names with error message: %s", error_buffer);
        FreeLibrary(hLibrary);
        return -1;
    }

    FreeLibrary(hLibrary);

    return ctx.found_id;
}

int *uk_ms_resource_find_ids_from_path(const char *target_path, int *number) {
    HMODULE hLibrary;
    char *error_buffer;
    resource_id_search_ctx ctx;

    if (!target_path) {
        uk_utils_stacktrace_push_msg("Specified target_path ptr is null");
        return NULL;
    }

    if (!uk_utils_is_file_exists(target_path)) {
        uk_utils_stacktrace_push_msg("Specified target path doesn't exist");
        return NULL;
    }

    if (!(hLibrary = LoadLibraryA(target_path))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("LoadLibraryA failed with error message: '%s'", error_buffer);
        return NULL;
    }

    ctx.ids = NULL;
    ctx.number = 0;

    if (!EnumResourceNames(hLibrary, RT_RCDATA, (ENUMRESNAMEPROC)ResIdProc, (LONG_PTR)&ctx)) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_get_last_werror(error_buffer);
            uk_utils_stacktrace_push_msg("Failed to enum resource names with error message: %s", error_buffer);
        }
        FreeLibrary(hLibrary);
        return NULL;
    }

    FreeLibrary(hLibrary);

    *number = ctx.number;

    return ctx.ids;
}

int *uk_ms_resource_find_ids_from_memory(int *number) {
    HMODULE hLibrary;
    char *error_buffer;
    resource_id_search_ctx ctx;

    if (!(hLibrary = GetModuleHandle(NULL))) {
        uk_utils_get_last_werror(error_buffer);
        uk_utils_stacktrace_push_msg("Failed to get our module handle with error message: '%s'", error_buffer);
        return NULL;
    }

    ctx.ids = NULL;
    ctx.number = 0;

    if (!EnumResourceNames(hLibrary, RT_RCDATA, (ENUMRESNAMEPROC)ResIdProc, (LONG_PTR)&ctx)) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_get_last_werror(error_buffer);
            uk_utils_stacktrace_push_msg("Failed to enum resource names with error message: %s", error_buffer);
        }
        FreeLibrary(hLibrary);
        return NULL;
    }

    FreeLibrary(hLibrary);

    *number = ctx.number;

    return ctx.ids;
}

