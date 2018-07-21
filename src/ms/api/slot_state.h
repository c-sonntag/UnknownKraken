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

#ifndef LIBMEMORYSLOT_SLOT_STATE_H
#define LIBMEMORYSLOT_SLOT_STATE_H

typedef enum {
    MS_SLOT_AVAILABLE,
    MS_SLOT_USED,
    MS_SLOT_CORRUPTED,
    MS_SLOT_UNKNOWN
} ms_slot_state;

#endif
