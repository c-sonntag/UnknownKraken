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

#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>

#include <string.h>

unsigned char *ue_bytes_create_from_string(const char *str) {
	unsigned char *new_bytes;
	size_t len;

	len = strlen(str);

	ue_safe_alloc(new_bytes, unsigned char, len);
	memcpy(new_bytes, str, len * sizeof(unsigned char));

	return new_bytes;
}

unsigned char *ue_bytes_create_from_bytes(unsigned char *bytes, size_t size) {
	unsigned char *new_bytes;

	ue_safe_alloc(new_bytes, unsigned char, size);
	memcpy(new_bytes, bytes, size * sizeof(unsigned char));

	return new_bytes;
}

void ue_int_to_bytes(int n, unsigned char *bytes) {
	bytes[0] = (n >> 24) & 0xFF;
	bytes[1] = (n >> 16) & 0xFF;
	bytes[2] = (n >> 8) & 0xFF;
	bytes[3] = n & 0xFF;
}

int ue_bytes_to_int(unsigned char *bytes) {
	int n;
	n = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
	return n;
}

bool ue_bytes_starts_with(unsigned char *data, size_t data_size, unsigned char *target, size_t target_size) {
	ue_check_parameter_or_return(data);
	ue_check_parameter_or_return(data_size > 0);
	ue_check_parameter_or_return(target);
	ue_check_parameter_or_return(target_size);

	if (data_size < target_size) {
		ue_logger_warn("Target > than data. The comparaison will be performed with the data size and not the target size.");
		return memcmp(data, target, data_size) == 0;
	}

	return memcmp(data, target, target_size) == 0;
}

bool ue_bytes_contains(unsigned char *data, size_t data_size, unsigned char *target, size_t target_size) {
	size_t i, counter;

	ue_check_parameter_or_return(data);
	ue_check_parameter_or_return(data_size > 0);
	ue_check_parameter_or_return(target);
	ue_check_parameter_or_return(target_size);

	if (data_size < target_size) {
		ue_logger_warn("Target > than data.");
		return false;
	}

	counter = 0;

	for (i = 0; i < data_size; i++) {
		if (data[i] == target[counter]) {
			counter++;
		} else {
			if (counter > 0) {
				i -= counter;
			}
			counter = 0;
		}
		if (counter == target_size) {
			return true;
		}
	}

	return false;
}
