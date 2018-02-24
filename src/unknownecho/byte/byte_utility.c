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
#include <unknownecho/system/alloc.h>

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
