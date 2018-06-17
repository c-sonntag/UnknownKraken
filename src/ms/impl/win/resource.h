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

#ifndef MEMORYSLOT_RESOURCE_H
#define MEMORYSLOT_RESOURCE_H

#include <ms/utils/bool.h>

#include <stddef.h>

unsigned char *ms_resource_load_from_path(const char *target_path, int id, size_t *size);

unsigned char *ms_resource_load_from_memory(int id, size_t *size);

bool ms_resource_save(const char *target_path, unsigned char *data, size_t size, int id);

bool ms_resource_exist(const char *target_path, int id);

int ms_resource_find_id_from_path(const char *target_path, unsigned char *data, size_t size);

int ms_resource_find_id_from_memory(unsigned char *data, size_t size);

int *ms_resource_find_ids_from_path(const char *target_path, int *number);

int *ms_resource_find_ids_from_memory(int *number);

#endif
