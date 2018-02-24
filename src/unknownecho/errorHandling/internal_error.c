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

#include <unknownecho/errorHandling/internal_error.h>

#include <stdlib.h>
#include <string.h>

char *ue_internal_error_get_description(ue_internal_error_type type) {
    size_t size;
	char *description;

	size = 50;
	description = (char *)malloc(size * sizeof(char));

	switch (type) {
		case UNKNOWNECHO_SUCCESS:
			strncpy(description, "No error detected", size);
		break;

		case UNKNOWNECHO_FILE_NOT_FOUND:
			strncpy(description, "File not found", size);
		break;

		case UNKNOWNECHO_NO_SUCH_MEMORY:
			strncpy(description, "No such memory available", size);
		break;

		case UNKNOWNECHO_INVALID_PARAMETER:
			strncpy(description, "Specified parameter is invalid", size);
		break;

		case UNKNOWNECHO_NO_INTERNET_CONNECTION:
			strncpy(description, "No internet connection", size);
		break;

		case UNKNOWNECHO_UNKNOWN_ERROR:
			strncpy(description, "Unknown error", size);
		break;

		default:
			strncpy(description, "Unknown error type", size);
	}

	description = (char *)realloc(description, (strlen(description) + 1) * sizeof(char));

	return description;
}

char *ue_internal_error_to_string(ue_error *e) {
    size_t size;
	char *error_buffer, *line_number_buffer, *prefix;

	error_buffer = NULL;
	line_number_buffer = NULL;
	prefix = NULL;

	line_number_buffer = (char *)malloc(10 * sizeof(char));
	sprintf(line_number_buffer, "%d", e->line_number);

	size = strlen("   at  (:)");
	size += strlen(e->func_name);
	size += strlen(e->file_name);
	size += strlen(line_number_buffer);
	free((void*)line_number_buffer);

	if (e->is_main_error) {
		size += strlen("Caused by: \n");
		size += strlen(e->description);
		prefix = (char *)malloc((strlen("Caused by: \n") + strlen(e->description) + 1) * sizeof(char));
		sprintf(prefix, "Caused by: %s\n", e->description);
	} else {
		prefix = (char *)malloc(sizeof(char));
		strcpy(prefix, "");
	}

	error_buffer = (char *)malloc((size + 1) * sizeof(char));
	sprintf(
		error_buffer,
		"%s   at %s (%s:%d)",
		prefix,
		e->func_name,
		e->file_name,
		e->line_number
	);

	free((void*)prefix);

	return error_buffer;
}

void ue_internal_error_print(ue_error *e, FILE *out) {
	char *error_buffer;

	error_buffer = ue_internal_error_to_string(e);

	fprintf(out, "%s\n", error_buffer);

	free((void*)error_buffer);
}
