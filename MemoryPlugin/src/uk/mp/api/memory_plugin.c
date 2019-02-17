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

#include <uk/mp/api/memory_plugin.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>
#include <uk/smo/smo.h>

#if defined(WITH_CRYPTO)

#include <uk/crypto/uecm.h>

#endif

#include <stdio.h>

#define EMPTY_SLOT_DATA "<AVAILABLE>"
#define EMPTY_SLOT_SIZE 11
#define RANDOM_ID_TRIES_NUMBER 10
#define MIN_SLOT_ID 100
#define MAX_SLOT_ID 200

uk_mp_memory_plugin *uk_mp_memory_plugin_create_new(uk_mp_entry *entry) {
    uk_mp_memory_plugin *plugin;
    uk_utils_byte_stream *stream;

    uk_utils_check_parameter_or_return(entry);

    stream = uk_mp_entry_get_data(entry);
    uk_utils_check_parameter_or_return(stream);

    uk_utils_safe_alloc(plugin, uk_mp_memory_plugin, 1);
    plugin->object_handle = NULL;
    plugin->id = -1;
    if ((plugin->slot = uk_ms_slot_create_from_memory(uk_utils_byte_stream_get_data(stream), uk_utils_byte_stream_get_size(stream))) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create slot from buffer");
        uk_utils_safe_free(plugin);
        return NULL;
    }

    return plugin;
}

uk_mp_memory_plugin *uk_mp_memory_plugin_create_empty() {
    uk_mp_memory_plugin *plugin;

    uk_utils_safe_alloc(plugin, uk_mp_memory_plugin, 1);
    plugin->object_handle = NULL;
    plugin->id = -1;
    if ((plugin->slot = uk_ms_slot_create_from_memory((unsigned char *)EMPTY_SLOT_DATA, EMPTY_SLOT_SIZE)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create slot from buffer");
        uk_utils_safe_free(plugin);
        return NULL;
    }

    return plugin;
}

void uk_mp_memory_plugin_destroy(uk_mp_memory_plugin *plugin) {
    if (plugin) {
        uk_smo_handle_destroy(plugin->object_handle);
        uk_ms_slot_destroy(plugin->slot);
        uk_utils_safe_free(plugin);
    }
}

int uk_mp_memory_plugin_save(uk_mp_memory_plugin *plugin, const char *target_path, void *crypto_metadata) {
    int *ids, ids_number, current_id, id, i, j;
    bool id_already_exist;
#if defined(WITH_CRYPTO)
    unsigned char *slot_data;
    size_t slot_size;
    uk_ms_slot *encrypted_slot;
#endif

    uk_utils_check_parameter_or_return(plugin);
    uk_utils_check_parameter_or_return(plugin->slot);

    id = -1;
#if defined(WITH_CRYPTO)
    slot_data = NULL;
    slot_size = 0;
    encrypted_slot = NULL;
#endif

    if ((ids = uk_ms_slot_find_ids_from_file(target_path, &ids_number)) == NULL) {
        /* @todo how to handle this special case ? */
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_logger_stacktrace("Failed to list existing slot ids");
            return -1;
        }
        id = MIN_SLOT_ID;
    }
    else {
        /**
         * Calculate a new id in range (MIN_SLOT_ID, MAX_SLOT_ID)
         * excluding the ids already used.
         *
         * @todo reduce the complexity, with an hash table for example
         */
        current_id = -1;
        for (i = 0; i < RANDOM_ID_TRIES_NUMBER; i++) {
            id = (rand() % (MAX_SLOT_ID - MIN_SLOT_ID + 1)) + MIN_SLOT_ID;
            id_already_exist = false;
            for (j = 0; j < ids_number; j++) {
                current_id = ids[j];
                if (current_id == id) {
                    id_already_exist = true;
                    break;
                }
            }
            if (!id_already_exist) {
                id = current_id;
                break;
            }
        }
        uk_utils_safe_free(ids);
    }

#if defined(WITH_CRYPTO)
    if (!uk_crypto_cipher_plain_data_default(plugin->slot->data, plugin->slot->size,
        uk_crypto_crypto_metadata_get_cipher_public_key((uk_crypto_crypto_metadata *)crypto_metadata), &slot_data, &slot_size)) {

        uk_utils_stacktrace_push_msg("Failed to cipher slot data");
        goto clean_up;
    }

    if ((encrypted_slot = uk_ms_slot_create_from_memory(slot_data, slot_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create encrypted slot from cipher data");
        goto clean_up;
    }

    if (!uk_ms_slot_save_to_file(encrypted_slot, id, target_path)) {
        uk_utils_stacktrace_push_msg("Failed to save encrypted slot to specified target file");
        goto clean_up;
    }
#else
    if (!uk_ms_slot_save_to_file(plugin->slot, id, target_path)) {
        uk_utils_stacktrace_push_msg("Failed to save slot to specified target file");
        return -1;
    }
#endif

clean_up:
    if (id == -1) {
        uk_utils_stacktrace_push_msg("No more slot available. Release plugin or increase the max number of plugins");
    }
#if defined(WITH_CRYPTO)
    uk_utils_safe_free(slot_data);
    uk_ms_slot_destroy(encrypted_slot);
#endif
    return id;
}

bool uk_mp_memory_plugin_save_at(uk_mp_memory_plugin *plugin, const char *target_path, void *crypto_metadata, int id) {
    bool result;
#if defined(WITH_CRYPTO)
    unsigned char *slot_data;
    size_t slot_size;
    uk_ms_slot *encrypted_slot;
#endif

    uk_utils_check_parameter_or_return(plugin);
    uk_utils_check_parameter_or_return(plugin->slot);

    result = false;
#if defined(WITH_CRYPTO)
    slot_data = NULL;
    slot_size = 0;
    encrypted_slot = NULL;
#endif

#if defined(WITH_CRYPTO)
    if (!uk_crypto_cipher_plain_data_default(plugin->slot->data, plugin->slot->size,
        uk_crypto_crypto_metadata_get_cipher_public_key((uk_crypto_crypto_metadata *)crypto_metadata), &slot_data, &slot_size)) {

        uk_utils_stacktrace_push_msg("Failed to cipher slot data");
        goto clean_up;
    }

    if ((encrypted_slot = uk_ms_slot_create_from_memory(slot_data, slot_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create encrypted slot from cipher data");
        goto clean_up;
    }

    if (!uk_ms_slot_save_to_file(encrypted_slot, id, target_path)) {
        uk_utils_stacktrace_push_msg("Failed to save encrypted slot to specified target file");
        goto clean_up;
    }
#else
    if (!uk_ms_slot_save_to_file(plugin->slot, id, target_path)) {
        uk_utils_stacktrace_push_msg("Failed to save slot to specified target file");
        goto clean_up;
    }
#endif

    result = true;

clean_up:
#if defined(WITH_CRYPTO)
    uk_utils_safe_free(slot_data);
    uk_ms_slot_destroy(encrypted_slot);
#endif
    return result;
}

uk_mp_memory_plugin *uk_mp_memory_plugin_load(int id, void *crypto_metadata) {
    uk_mp_memory_plugin *plugin;
    uk_ms_slot *loaded_slot;
    uk_smo_handle *object_handle_opened;
    char *string_id;

#if defined(WITH_CRYPTO)
    unsigned char *slot_data;
    size_t slot_size;

    if (!crypto_metadata) {
        uk_utils_stacktrace_push_msg("WITH_CRYPTO is set but crypto_metadata ptr is null");
        return NULL;
    }
#else
    (void)crypto_metadata;
#endif

    if (id < MIN_SLOT_ID || id > MAX_SLOT_ID) {
        uk_utils_stacktrace_push_msg("Specified id %d is out of bound of (%d, %d)", id, MIN_SLOT_ID, MAX_SLOT_ID);
        return NULL;
    }

    if ((loaded_slot = uk_ms_slot_load_from_memory(id)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to load slot with id %d", id);
        return NULL;
    }

#if defined(WITH_CRYPTO)
    if (!uk_crypto_decipher_cipher_data_default(uk_ms_slot_get_data(loaded_slot),
        uk_ms_slot_get_size(loaded_slot), uk_crypto_crypto_metadata_get_cipher_private_key(
        (uk_crypto_crypto_metadata *)crypto_metadata), &slot_data, &slot_size)) {

        uk_ms_slot_destroy(loaded_slot);
        uk_utils_stacktrace_push_msg("Failed to decipher slot data");
        return NULL;
    }

    uk_utils_safe_free(loaded_slot->data);
    loaded_slot->data = slot_data;
    loaded_slot->size = slot_size;
#endif

    uk_utils_safe_alloc(string_id, char, 3);
    sprintf(string_id, "%d", id);

    if ((object_handle_opened = uk_smo_open(string_id, uk_ms_slot_get_data(loaded_slot), uk_ms_slot_get_size(loaded_slot))) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to load object handle from loaded slot");
        uk_ms_slot_destroy(loaded_slot);
        uk_utils_safe_free(string_id);
        return NULL;
    }

    uk_utils_safe_free(string_id);

    uk_utils_safe_alloc(plugin, uk_mp_memory_plugin, 1);
    plugin->slot = loaded_slot;
    plugin->object_handle = object_handle_opened;
    plugin->id = id;

    return plugin;
}

void uk_mp_memory_plugin_unload(uk_mp_memory_plugin *plugin) {
    if (!plugin) {
        uk_utils_logger_warn("Specified ptr is null. Already unload ?");
        return;
    }

    if (!plugin->object_handle) {
        uk_utils_logger_warn("Object handle ptr of specified plugin is null. Already unload ?");
    }
    else if (!uk_smo_close(plugin->object_handle)) {
        uk_utils_logger_error("Failed to close object handle");
    }
    plugin->object_handle = NULL;

    if (!plugin->slot) {
        uk_utils_logger_warn("Slot ptr of specified plugin is null. Already unload ?");
    }
    else {
        uk_ms_slot_destroy(plugin->slot);
        plugin->slot = NULL;
    }

    uk_utils_safe_free(plugin);
}

void *uk_mp_memory_plugin_get_function(uk_mp_memory_plugin *plugin, const char *function_name) {
    void *function_ptr;

    if (!plugin) {
        uk_utils_stacktrace_push_msg("Specified plugin ptr is null");
        return NULL;
    }

    if (!plugin->object_handle) {
        uk_utils_stacktrace_push_msg("Object handle ptr of specified plugin is null");
        return NULL;
    }

    if (!function_name) {
        uk_utils_stacktrace_push_msg("Specified function name ptr is null");
        return NULL;
    }

    if ((function_ptr = uk_smo_get_function(plugin->object_handle, function_name)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to find speicified function in loaded shared object handle");
        return NULL;
    }

    return function_ptr;
}

bool uk_mp_memory_plugin_update(uk_mp_memory_plugin *plugin, uk_mp_entry *entry, void *crypto_metadata) {
    bool result;
    char *string_id;
    uk_utils_byte_stream *stream;
    const char *our_process_name;

    uk_utils_check_parameter_or_return(plugin);
    uk_utils_check_parameter_or_return(entry);
    stream = uk_mp_entry_get_data(entry);
    uk_utils_check_parameter_or_return(stream);

    if (plugin->object_handle) {
        if (!uk_smo_close(plugin->object_handle)) {
            uk_utils_stacktrace_push_msg("Failed to close object handle");
            return false;
        }
    }

    result = false;
    string_id = NULL;
    our_process_name = NULL;

    uk_ms_slot_destroy(plugin->slot);

    if ((plugin->slot = uk_ms_slot_create_from_memory(uk_utils_byte_stream_get_data(stream),
        uk_utils_byte_stream_get_size(stream))) == NULL) {

        uk_utils_stacktrace_push_msg("Failed to create new slot from memory");
        goto clean_up;
    }

    uk_utils_safe_alloc(string_id, char, 3);
    sprintf(string_id, "%d", plugin->id);

    if ((plugin->object_handle = uk_smo_open(string_id, uk_ms_slot_get_data(plugin->slot), uk_ms_slot_get_size(plugin->slot))) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to load new object handle");
        goto clean_up;
    }

    if ((our_process_name = uk_utils_get_current_process_name()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to get our process name");
        goto clean_up;
    }

    if (!uk_mp_memory_plugin_save_at(plugin, our_process_name, crypto_metadata, plugin->id)) {
        uk_utils_stacktrace_push_msg("Failed to save new plugin updates at the same id");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_utils_safe_free(string_id);
    uk_utils_safe_free(our_process_name);
    return result;
}

bool uk_mp_memory_plugin_release(uk_mp_memory_plugin *plugin) {
    bool result;
    int slot_id;

    uk_utils_check_parameter_or_return(plugin);

    if (plugin->object_handle) {
        if (!uk_smo_close(plugin->object_handle)) {
            uk_utils_stacktrace_push_msg("Failed to close object handle");
            return false;
        }
    }

    slot_id = plugin->id;

    uk_ms_slot_destroy(plugin->slot);

    if ((plugin->slot = uk_ms_slot_create_from_memory((unsigned char *)EMPTY_SLOT_DATA, EMPTY_SLOT_SIZE)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create empty slot from memory");
        return false;
    }

    if ((result = uk_ms_slot_save_to_memory(plugin->slot, slot_id)) == false) {
        uk_utils_stacktrace_push_msg("Failed to save empty plugin");
    }

    uk_ms_slot_destroy(plugin->slot);

    return result;
}
