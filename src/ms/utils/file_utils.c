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

#include <ms/utils/file_utils.h>
#include <ms/utils/alloc.h>

#include <ei/ei.h>

#include <Windows.h>
#include <stdio.h>

bool ms_is_file_exists(const char *file_name) {
#if defined(__unix__)
	struct stat st;
#elif defined(_WIN32) || defined(_WIN64)
	DWORD dw_attrib;
#else
#error "OS not supported"
#endif

#if defined(__unix__)
	if (stat(file_name, &st) == 0) {
		return S_ISREG(st.st_mode);
	}
	return false;
#elif defined(_WIN32) || defined(_WIN64)
	dw_attrib = GetFileAttributesA(file_name);
	if (dw_attrib != INVALID_FILE_ATTRIBUTES &&
		dw_attrib != FILE_ATTRIBUTE_DIRECTORY) {
		return true;
	}
#endif

	return false;
}

size_t ms_get_file_size(FILE *fd) {
	size_t file_size;

	file_size = -1;

	if (!fd) {
		return -1;
	}

	fseek(fd, 0, SEEK_END);
	file_size = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	return file_size;
}

unsigned char *ms_read_binary_file(const char *file_name, size_t *size) {
	unsigned char *out;
	FILE *fd;
	size_t file_size;

	out = NULL;

	ei_check_parameter_or_return(file_name);

	if (!(fd = fopen(file_name, "rb"))) {
		ei_stacktrace_push_errno();
		return NULL;
	}

	if ((file_size = ms_get_file_size(fd)) <= 0) {
		ei_stacktrace_push_msg("Empty file");
		goto clean_up;
	}

	ms_safe_alloc_or_goto(out, unsigned char, file_size, clean_up);

	if (fread(out, file_size, 1, fd) == 0) {
		ms_safe_free(out);
		ei_stacktrace_push_errno();
	}

	*size = file_size;

clean_up:
	fclose(fd);

	return out;
}
