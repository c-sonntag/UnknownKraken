/******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                       *
 *                                                                            *
 * This file is part of LibMemoryPlugin.                                      *
 *                                                                            *
 *   LibMemoryPlugin is free software: you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by     *
 *   the Free Software Foundation, either version 3 of the License, or        *
 *   (at your option) any later version.                                      *
 *                                                                            *
 *   LibMemoryPlugin is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of           *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *
 *   GNU General Public License for more details.                             *
 *                                                                            *
 *   You should have received a copy of the GNU General Public License        *
 *   along with LibMemoryPlugin.  If not, see <http://www.gnu.org/licenses/>. *
 ******************************************************************************/

#ifndef MEMORYPLUGIN_ENTRY_H
#define MEMORYPLUGIN_ENTRY_H

#include <ueum/ueum.h>

#include <stddef.h>

typedef struct {
    ueum_byte_stream *data;
} mp_entry;

mp_entry *mp_entry_create();

void mp_entry_destroy(mp_entry *entry);

bool mp_entry_add_stream(mp_entry *entry, ueum_byte_stream *data);

bool mp_entry_add_bytes(mp_entry *entry, unsigned char *data, size_t data_size);

bool mp_entry_add_file(mp_entry *entry, const char *file_name);

ueum_byte_stream *mp_entry_get_data(mp_entry *entry);

#endif
