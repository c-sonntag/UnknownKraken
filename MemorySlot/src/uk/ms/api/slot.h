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

#ifndef UnknownKrakenMemorySlot_SLOT_H
#define UnknownKrakenMemorySlot_SLOT_H

#include <uk/ms/api/slot_struct.h>
#include <uk/ms/api/slot_state.h>
#include <uk/utils/ueum.h>

#include <stddef.h>

uk_ms_slot *uk_ms_slot_create_from_file(const char *file_name);

uk_ms_slot *uk_ms_slot_create_from_memory(unsigned char *buffer, size_t size);

void uk_ms_slot_destroy(uk_ms_slot *slot);

int uk_ms_slot_get_id(uk_ms_slot *slot);

uk_ms_slot_state uk_ms_slot_get_state(uk_ms_slot *slot);

unsigned char *uk_ms_slot_get_data(uk_ms_slot *slot);

size_t uk_ms_slot_get_size(uk_ms_slot *slot);

bool uk_ms_slot_save_to_file(uk_ms_slot *slot, int id, const char *file_name);

bool uk_ms_slot_save_to_memory(uk_ms_slot *slot, int id);

uk_ms_slot *uk_ms_slot_load_from_memory(int id);

bool uk_ms_slot_exist_from_file(int id, const char *file_name);

bool uk_ms_slot_exist_from_memory(int id);

int uk_ms_slot_find_id_from_path(const char *file_name, uk_ms_slot *slot);

int uk_ms_slot_find_id_from_memory(uk_ms_slot *slot);

int *uk_ms_slot_find_ids_from_file(const char *file_name, int *number);

int *uk_ms_slot_find_ids_from_memory(int *number);
    
#endif
