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

#include <uk/mp/mp.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

#if defined(WITH_CRYPTO)

#include <uk/crypto/uecm.h>

#endif

#include <stdlib.h>
#include <time.h>

/**
* The purpose of this example is to show how to create
* a plugin from a library stored in disk, and save it in a
* target program.
* Example of usage: ./create_new_plugin_example load_plugin_example.exe hello_world_plugin.dll
* The returned id will be used to load or update the created plugin.
*/
int main(int argc, char **argv) {
    uk_mp_memory_plugin *plugin;
    uk_mp_entry *entry;
    int plugin_id;
    void *crypto_metadata;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <plugin_source_path> <target_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    uk_utils_init();

#if defined(WITH_CRYPTO)
    uk_crypto_init();
#endif

    plugin = NULL;
    entry = NULL;
    crypto_metadata = NULL;

    if (!uk_utils_is_file_exists(argv[1])) {
        uk_utils_stacktrace_push_msg("Specified plugin source file '%s' doesn't exist", argv[1]);
        goto clean_up;
    }

    if (!uk_utils_is_file_exists(argv[2])) {
        uk_utils_stacktrace_push_msg("Specified plugin target file '%s' doesn't exist", argv[2]);
        goto clean_up;
    }

    srand((unsigned int)time(0));

    entry = uk_mp_entry_create();
    uk_mp_entry_add_file(entry, argv[1]);
#if defined(WITH_CRYPTO)
    if ((crypto_metadata = (uk_crypto_crypto_metadata *)uk_crypto_crypto_metadata_create_default()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create random crypto metadata");
        goto clean_up;
    }
    if (!uk_crypto_crypto_metadata_write((uk_crypto_crypto_metadata *)crypto_metadata, "metadata", "uid", "password")) {
        uk_utils_stacktrace_push_msg("Failed to write crypto metadata");
        goto clean_up;
    }
#endif

    /* Create new plugin from buffer */
    uk_utils_logger_info("Creating new plugin from file...");
    if ((plugin = uk_mp_memory_plugin_create_new(entry)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create new plugin");
        goto clean_up;
    }
    uk_utils_logger_info("New plugin created");

    /**
    * Save the plugin into the target path (exec or shared object). It returned the
    * corresponding id of the created plugin.
    */
    uk_utils_logger_info("Saving plugin to target file...");
    if ((plugin_id = uk_mp_memory_plugin_save(plugin, argv[2], crypto_metadata)) == -1) {
        uk_utils_stacktrace_push_msg("Failed to save new plugin to %s", argv[2]);
        goto clean_up;
    }

    uk_utils_logger_info("Succeed to save new plugin with id %d", plugin_id);

clean_up:
    uk_mp_entry_destroy(entry);
    /* Destroy only the object content and not the saved plugin */
    uk_mp_memory_plugin_destroy(plugin);
#if defined(WITH_CRYPTO)
    uk_crypto_crypto_metadata_destroy((uk_crypto_crypto_metadata *)crypto_metadata);
    uk_crypto_uninit();
#endif
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return EXIT_SUCCESS;
}
