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

#ifndef LIBMEMORYSLOT_SLOT_H
#define LIBMEMORYSLOT_SLOT_H

#include <ms/api/slot_struct.h>
#include <ms/api/slot_state.h>
#include <ms/utils/bool.h>

#include <stddef.h>

ms_slot *ms_slot_create_from_file(const char *file_name);

ms_slot *ms_slot_create_from_memory(unsigned char **buffer, size_t size);

void ms_slot_destroy(ms_slot *slot);

int ms_slot_get_id(ms_slot *slot);

ms_slot_state ms_slot_get_state(ms_slot *slot);

unsigned char *ms_slot_get_data(ms_slot *slot);

size_t ms_slot_get_size(ms_slot *slot);

bool ms_slot_save_to_file(ms_slot *slot, int id, const char *file_name);

bool ms_slot_save_to_memory(ms_slot *slot, int id);

ms_slot *ms_slot_load(int id);

#endif
