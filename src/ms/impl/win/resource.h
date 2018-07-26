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

#ifndef MEMORYSLOT_RESOURCE_H
#define MEMORYSLOT_RESOURCE_H

#include <ueum/ueum.h>

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
