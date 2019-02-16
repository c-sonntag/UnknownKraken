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

#ifndef MEMORYPLUGIN_MEMORY_PLUGIN_H
#define MEMORYPLUGIN_MEMORY_PLUGIN_H

#include <mp/api/entry.h>
#include <ueum/ueum.h>
#include <smo/smo.h>
#include <ms/ms.h>

#include <stddef.h>

typedef struct {
    int id;
    ms_slot *slot;
    smo_handle *object_handle;
} mp_memory_plugin;

mp_memory_plugin *mp_memory_plugin_create_new(mp_entry *entry);

mp_memory_plugin *mp_memory_plugin_create_empty();

void mp_memory_plugin_destroy(mp_memory_plugin *plugin);

int mp_memory_plugin_save(mp_memory_plugin *plugin, const char *target_path, void *crypto_metadata);

bool mp_memory_plugin_save_at(mp_memory_plugin *plugin, const char *target_path, void *crypto_metadata, int id);

mp_memory_plugin *mp_memory_plugin_load(int id, void *crypto_metadata);

void mp_memory_plugin_unload(mp_memory_plugin *plugin);

void *mp_memory_plugin_get_function(mp_memory_plugin *plugin, const char *function_name);

bool mp_memory_plugin_update(mp_memory_plugin *plugin, mp_entry *entry, void *crypto_metadata);

bool mp_memory_plugin_release(mp_memory_plugin *plugin);

#endif
