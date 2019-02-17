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

#ifndef UnknownKrakenMemoryPlugin_MEMORY_PLUGIN_H
#define UnknownKrakenMemoryPlugin_MEMORY_PLUGIN_H

#include <uk/mp/api/entry.h>
#include <uk/utils/ueum.h>
#include <uk/smo/smo.h>
#include <uk/ms/ms.h>

#include <stddef.h>

typedef struct {
    int id;
    uk_ms_slot *slot;
    uk_smo_handle *object_handle;
} uk_mp_memory_plugin;

uk_mp_memory_plugin *uk_mp_memory_plugin_create_new(uk_mp_entry *entry);

uk_mp_memory_plugin *uk_mp_memory_plugin_create_empty();

void uk_mp_memory_plugin_destroy(uk_mp_memory_plugin *plugin);

int uk_mp_memory_plugin_save(uk_mp_memory_plugin *plugin, const char *target_path, void *crypto_metadata);

bool uk_mp_memory_plugin_save_at(uk_mp_memory_plugin *plugin, const char *target_path, void *crypto_metadata, int id);

uk_mp_memory_plugin *uk_mp_memory_plugin_load(int id, void *crypto_metadata);

void uk_mp_memory_plugin_unload(uk_mp_memory_plugin *plugin);

void *uk_mp_memory_plugin_get_function(uk_mp_memory_plugin *plugin, const char *function_name);

bool uk_mp_memory_plugin_update(uk_mp_memory_plugin *plugin, uk_mp_entry *entry, void *crypto_metadata);

bool uk_mp_memory_plugin_release(uk_mp_memory_plugin *plugin);

#endif
