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

#include <unknownecho/byte/byte_split.h>
#include <unknownecho/alloc.h>
#include <ei/ei.h>

#include <string.h>

unsigned char **ue_byte_split(unsigned char *bytes, size_t bytes_len, unsigned char *delimiter, size_t delimiter_len, size_t *count, size_t **sizes) {
	unsigned char **result;
	size_t i, j, k, l, m, n, *tmp_sizes, tmp_count;
	int tmp_len;

	result = NULL;
	tmp_count = 0;
	k = 0;
	l = 0;
	m = 0;
	n = 0;
	tmp_sizes = NULL;

	if (delimiter_len > bytes_len) {
		return NULL;
	}

	for (i = 0, j = 0; i < bytes_len; i++) {
		if (delimiter_len == 1) {
			if (bytes[i] == delimiter[0]) {
				if (!result) {
					ue_safe_alloc(result, unsigned char *, 1);
					ue_safe_alloc(tmp_sizes, size_t, 1);
				} else {
					ue_safe_realloc(result, unsigned char *, tmp_count, 1);
					ue_safe_realloc(tmp_sizes, size_t, tmp_count, 1);
				}
				tmp_len = k - l + 1;
				if (tmp_len <= 0) {
					ei_stacktrace_push_msg("Invalid k - l + 1. k:%d l:%d", k, l);
					goto clean_up_error;
				}
				tmp_sizes[tmp_count] = tmp_len-1;
				ue_safe_alloc(result[tmp_count], unsigned char, tmp_sizes[tmp_count]);
				memcpy(result[tmp_count], bytes + l, (k - l) * sizeof(unsigned char));
				tmp_count = tmp_count + 1;
				k = i+1;
				l = i+1;
				m = 0;
			} else {
				k = i+1;
				m++;
			}
		}
		else if (j == delimiter_len-1) {
			if (!result) {
				ue_safe_alloc(result, unsigned char *, 1);
				ue_safe_alloc(tmp_sizes, size_t, 1);
			} else {
				ue_safe_realloc(result, unsigned char *, tmp_count, 1);
				ue_safe_realloc(tmp_sizes, size_t, tmp_count, 1);
			}

			tmp_len = m;
			if (tmp_len <= 0) {
				ei_stacktrace_push_msg("Invalid k - l + 1. k:%d l:%d", k, l);
				goto clean_up_error;
			}
			if (delimiter_len + k == bytes_len) {
				tmp_sizes[tmp_count] = k;
			} else {
				tmp_sizes[tmp_count] = tmp_len;
			}
			ue_safe_alloc(result[tmp_count], unsigned char, tmp_sizes[tmp_count]);
			if (delimiter_len + k == bytes_len) {
				memcpy(result[tmp_count], bytes + n, k * sizeof(unsigned char));
			} else {
				memcpy(result[tmp_count], bytes + k - m, m * sizeof(unsigned char));
			}
			tmp_count += 1;
			//k = 0;
			l = 0;
			j = 0;
			m = 0;
			n = k;
		} else {
			if (bytes[i] == delimiter[j]) {
				j++;
				l++;
			} else {
				k = i+1;
				j = 0;
				m++;
			}
		}
	}

	if (m != 0) {
		if (tmp_count == 0 && l != delimiter_len) {
			goto clean_up_error;
		}
		ue_safe_realloc(result, unsigned char *, tmp_count, 1);
		ue_safe_realloc(tmp_sizes, size_t, tmp_count, 1);
		tmp_sizes[tmp_count] = m;
		ue_safe_alloc(result[tmp_count], unsigned char, tmp_sizes[tmp_count]);
		memcpy(result[tmp_count], bytes + bytes_len - m, m * sizeof(unsigned char));
		tmp_count += 1;
	}

	*sizes = tmp_sizes;
	*count = tmp_count;

	return result;

clean_up_error:
	if (result) {
		if (tmp_count > 0) {
			for (i = 0; i < tmp_count; i++) {
				ue_safe_free(result[i]);
			}
		}
		ue_safe_free(result);
	}
	if (tmp_sizes) {
		ue_safe_free(tmp_sizes);
	}
	return NULL;
}

bool ue_byte_split_append(ue_byte_vector *vector, unsigned char *bytes, size_t bytes_len, unsigned char *delimiter, size_t delimiter_len) {
	unsigned char **split_elements;
	size_t split_count, *split_sizes, i;

	ei_check_parameter_or_return(vector);
	ei_check_parameter_or_return(bytes);
	ei_check_parameter_or_return(bytes_len > 0);
	ei_check_parameter_or_return(delimiter);
	ei_check_parameter_or_return(delimiter_len > 0);

	if (!(split_elements = ue_byte_split(bytes, bytes_len, delimiter, delimiter_len, &split_count, &split_sizes))) {
		ei_stacktrace_push_msg("Failed to split this bytes stream with this delimiter");
		return false;
	}

	for (i = 0; i < split_count; i++) {
		if (!ue_byte_vector_append_bytes(vector, split_elements[i], split_sizes[i])) {
			ei_logger_error("Failed to append element %ld of size %ld", i, split_sizes[i]);
		}
	}

	for (i = 0; i < split_count; i++) {
		ue_safe_free(split_elements[i]);
	}

	ue_safe_free(split_elements);
	ue_safe_free(split_sizes);

	return true;
}
