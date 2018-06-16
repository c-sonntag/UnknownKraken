/******************************************************************************
* Copyright (C) 2018 by Charly Lamothe                                        *
*                                                                             *
* This file is part of LibMemorySlot.                                         *
*                                                                             *
*   LibMemorySlot is free software: you can redistribute it and/or modify     *
*   it under the terms of the GNU General Public License as published by      *
*   the Free Software Foundation, either version 3 of the License, or         *
*   (at your option) any later version.                                       *
*                                                                             *
*   LibMemorySlot is distributed in the hope that it will be useful,          *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
*   GNU General Public License for more details.                              *
*                                                                             *
*   You should have received a copy of the GNU General Public License         *
*   along with LibMemorySlot.  If not, see <http://www.gnu.org/licenses/>.    *
*******************************************************************************/

#include <ms/impl/win/resource.h>
#include <ms/utils/alloc.h>
#include <ms/utils/file_utils.h>

#include <ei/ei.h>

#include <Windows.h>
#include <string.h>

static unsigned char *resource_load_internal(HMODULE hLibrary, int id, size_t *size) {
	unsigned char *data, *loaded_data;
	HRSRC hResource;
	HGLOBAL hResourceLoaded;
	char *error_buffer;

	ei_check_parameter_or_return(hLibrary);
	ei_check_parameter_or_return(id > 0);

	data = NULL;
	loaded_data = NULL;
	hResource = NULL;
	hResourceLoaded = NULL;
	error_buffer = NULL;

	if (!(hResource = FindResourceA(hLibrary, MAKEINTRESOURCE(id), RT_RCDATA))) {
		ei_get_last_werror(error_buffer);
		ei_stacktrace_push_msg("Failed to find resource with error message: '%s'", error_buffer);
		return NULL;
	}

	if (!(hResourceLoaded = LoadResource(hLibrary, hResource))) {
		ei_get_last_werror(error_buffer);
		ei_stacktrace_push_msg("Failed to load resource with error message: '%s'", error_buffer);
		return NULL;
	}

	if (!(loaded_data = (LPBYTE)LockResource(hResourceLoaded))) {
		ei_get_last_werror(error_buffer);
		ei_stacktrace_push_msg("Failed to lock resource with error message: '%s'", error_buffer);
		return NULL;
	}

	*size = SizeofResource(hLibrary, hResource);

	ms_safe_alloc(data, unsigned char, *size);
	memcpy(data, loaded_data, *size * sizeof(unsigned char));
	
	return data;
}

unsigned char *ms_resource_load_from_path(const char *target_path, int id, size_t *size) {
	unsigned char *data;
	HMODULE hLibrary;
	char *error_buffer;

	ei_check_parameter_or_return(target_path);
	ei_check_parameter_or_return(id > 0);

	data = NULL;
	error_buffer = NULL;

	if (!ms_is_file_exists(target_path)) {
		ei_stacktrace_push_msg("Specified target path doesn't exist");
		return NULL;
	}
	
	if (!(hLibrary = LoadLibraryA(target_path))) {
		ei_get_last_werror(error_buffer);
		ei_stacktrace_push_msg("LoadLibraryA failed with error message: '%s'", error_buffer);
		return NULL;
	}
	
	if (!(data = resource_load_internal(hLibrary, id, size))) {
		ei_stacktrace_push_msg("Failed to load resource");
		return NULL;
	}

	FreeLibrary(hLibrary);

	return data;
}

unsigned char *ms_resource_load_from_memory(int id, size_t *size) {
	unsigned char *data;
	HMODULE hLibrary;
	char *error_buffer;
	size_t temp_size;

	ei_check_parameter_or_return(id > 0);

	data = NULL;
	error_buffer = NULL;
	*size = 0;

	if (!(hLibrary = GetModuleHandle(NULL))) {
		ei_get_last_werror(error_buffer);
		ei_stacktrace_push_msg("Failed to get our module handle with error message: '%s'", error_buffer);
		return NULL;
	}

	if (!(data = resource_load_internal(hLibrary, id, &temp_size))) {
		ei_stacktrace_push_msg("Failed to load resource");
		return NULL;
	}

	*size = temp_size;

	FreeLibrary(hLibrary);

	return data;
}

bool ms_resource_save(const char *target_path, unsigned char *data, size_t size, int id) {
	bool result;
	HANDLE hResource;
	char *error_buffer;

	ei_check_parameter_or_return(target_path);
	ei_check_parameter_or_return(data);
	ei_check_parameter_or_return(size > 0);
	ei_check_parameter_or_return(id > 0);

	result = false;
	hResource = NULL;
	error_buffer = NULL;

	if (!(hResource = BeginUpdateResourceA(target_path, FALSE))) {
		ei_get_last_werror(error_buffer);
		ei_stacktrace_push_msg("BeginUpdateResourceA failed with error message: '%s'", error_buffer);
		goto clean_up;
	}

	if (UpdateResourceA(hResource,
		RT_RCDATA,
		MAKEINTRESOURCE(id),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPVOID)data,
		size) == FALSE) {

		ei_get_last_werror(error_buffer);
		ei_stacktrace_push_msg("UpdateResourceA failed with error message: '%s'", error_buffer);
		goto clean_up;
	}

	if (EndUpdateResourceA(hResource, FALSE) == FALSE) {
		ei_get_last_werror(error_buffer);
		ei_stacktrace_push_msg("EndUpdateResourceA failed with error message: '%s'", error_buffer);
		goto clean_up;
	}

	result = true;

clean_up:
	CloseHandle(hResource);
	return result;
}

typedef struct {
	int id;
	bool found;
} res_name_search;

BOOL CALLBACK ResNameProc(HANDLE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG lParam) {
	res_name_search *rns;
	char *resource_name;

	rns = (res_name_search *)lParam;

	if (IS_INTRESOURCE(lpszName)) {
		ei_safe_alloc(resource_name, char, 3);
		wsprintf(resource_name, "%d", (USHORT)lpszName);
		rns->found = atoi(resource_name) == rns->id;
		ei_safe_free(resource_name);
	}

	return TRUE;
}

bool ms_resource_exist(const char *target_path, int id) {
	HANDLE hResource;
	res_name_search rns;
	char *error_buffer;

	rns.id = id;
	rns.found = false;

	if (!(hResource = LoadLibraryA(target_path))) {
		ei_get_last_werror(error_buffer);
		ei_stacktrace_push_msg("Failed to load library with error message: %s", error_buffer);
		return false;
	}

	if (!EnumResourceNames(hResource, RT_RCDATA, (ENUMRESNAMEPROC)ResNameProc, &rns)) {
		ei_get_last_werror(error_buffer);
		ei_stacktrace_push_msg("Failed to enum resource names with error message: %s", error_buffer);
		FreeLibrary(hResource);
		return false;
	}

	FreeLibrary(hResource);

	return rns.found;
}
