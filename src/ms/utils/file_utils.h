/*******************************************************************************
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

#ifndef MEMORYSLOT_FILE_UTILS_H
#define MEMORYSLOT_FILE_UTILS_H

#include <ms/utils/bool.h>

#include <stddef.h>
#include <stdio.h>

bool ms_is_file_exists(const char *file_name);

size_t ms_get_file_size(FILE *fd);

unsigned char *ms_read_binary_file(const char *file_name, size_t *size);

#endif
