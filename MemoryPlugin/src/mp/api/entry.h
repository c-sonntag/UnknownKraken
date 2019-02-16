/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibMemoryPlugin.                                       *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

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
