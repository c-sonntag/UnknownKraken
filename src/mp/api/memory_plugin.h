/*****************************************************************************
* Copyright (C) 2018 by Charly Lamothe										 *
*																		     *
* This file is part of LibMemoryPlugin.                                      *
*																			 *
*   LibMemoryPlugin is free software: you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by	 *
*   the Free Software Foundation, either version 3 of the License, or		 *
*   (at your option) any later version.										 *
*																			 *
*   LibMemoryPlugin is distributed in the hope that it will be useful,		 *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of			 *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the			 *
*   GNU General Public License for more details.							 *
*																			 *
*   You should have received a copy of the GNU General Public License        *
*   along with LibMemoryPlugin.  If not, see <http://www.gnu.org/licenses/>. *
******************************************************************************/

#ifndef MEMORYPLUGIN_sMEMORY_PLUGIN_H
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
