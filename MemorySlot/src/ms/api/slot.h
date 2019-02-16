/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibMemorySlot.                                         *
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

#ifndef LIBMEMORYSLOT_SLOT_H
#define LIBMEMORYSLOT_SLOT_H

#include <ms/api/slot_struct.h>
#include <ms/api/slot_state.h>
#include <ueum/ueum.h>

#include <stddef.h>

ms_slot *ms_slot_create_from_file(const char *file_name);

ms_slot *ms_slot_create_from_memory(unsigned char *buffer, size_t size);

void ms_slot_destroy(ms_slot *slot);

int ms_slot_get_id(ms_slot *slot);

ms_slot_state ms_slot_get_state(ms_slot *slot);

unsigned char *ms_slot_get_data(ms_slot *slot);

size_t ms_slot_get_size(ms_slot *slot);

bool ms_slot_save_to_file(ms_slot *slot, int id, const char *file_name);

bool ms_slot_save_to_memory(ms_slot *slot, int id);

ms_slot *ms_slot_load_from_memory(int id);

bool ms_slot_exist_from_file(int id, const char *file_name);

bool ms_slot_exist_from_memory(int id);

int ms_slot_find_id_from_path(const char *file_name, ms_slot *slot);

int ms_slot_find_id_from_memory(ms_slot *slot);

int *ms_slot_find_ids_from_file(const char *file_name, int *number);

int *ms_slot_find_ids_from_memory(int *number);
    
#endif
