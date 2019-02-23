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

#ifndef UnknownKrakenMemoryPlugin_ENTRY_H
#define UnknownKrakenMemoryPlugin_ENTRY_H

#include <uk/utils/ueum.h>

#include <stddef.h>

typedef struct {
    uk_utils_byte_stream *data;
} uk_mp_entry;

uk_mp_entry *uk_mp_entry_create();

void uk_mp_entry_destroy(uk_mp_entry *entry);

bool uk_mp_entry_add_stream(uk_mp_entry *entry, uk_utils_byte_stream *data);

bool uk_mp_entry_add_bytes(uk_mp_entry *entry, unsigned char *data, size_t data_size);

bool uk_mp_entry_add_file(uk_mp_entry *entry, const char *file_name);

uk_utils_byte_stream *uk_mp_entry_get_data(uk_mp_entry *entry);

#endif