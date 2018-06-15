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

#ifndef LIBMEMORYSLOT_SLOT_STRUCT_H
#define LIBMEMORYSLOT_SLOT_STRUCT_H

#include <ms/api/slot_state.h>

#include <stddef.h>

typedef struct {
	int id;
	ms_slot_state state;
	unsigned char *data;
	size_t size;
} ms_slot;

#endif
