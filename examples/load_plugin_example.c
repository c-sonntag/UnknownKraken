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

#include <mp/mp.h>
#include <ei/ei.h>

#if defined(WITH_CRYPTO)

#include <uecm/uecm.h>

#endif

#include <stdlib.h>
#include <time.h>
#include <stdio.h>

/**
 * The purpose of this example is to show how to load
 * a plugin from the memory of the running process.
 * To do that, first we need to save the memory plugin onto
 * the program of this example, by running create_new_plugin_example program.
 * After the plugin is saved, we can load it and its functions by name.
 */
int main(int argc, char **argv) {
    mp_memory_plugin *plugin;
    typedef void(*hello_world_func)(void);
    hello_world_func hello_world;
    int plugin_id;
    void *crypto_metadata;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <plugin_id>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    ei_init();

    srand((unsigned int)time(0));
    plugin = NULL;
    plugin_id = atoi(argv[1]);

#if defined(WITH_CRYPTO)
    uecm_init();

    if ((crypto_metadata = (void *)uecm_crypto_metadata_create_empty()) == NULL) {
        ei_stacktrace_push_msg("Failed to create empty crypto metadata object");
        goto clean_up;
    }

    if (!uecm_crypto_metadata_read((uecm_crypto_metadata *)crypto_metadata,
        "metadata", "uid", "password")) {

        ei_stacktrace_push_msg("Failed to read crypto metadata");
        goto clean_up;
    }
#else
    crypto_metadata = NULL;
#endif

    /* Load plugin from id */
    ei_logger_info("Loading memory plugin from id %d...", plugin_id);
    if ((plugin = mp_memory_plugin_load(plugin_id, crypto_metadata)) == NULL) {
        ei_stacktrace_push_msg("Failed to load plugin with id %d", plugin_id);
        goto clean_up;
    }
    ei_logger_info("Memory plugin loaded");

    /* Get a function from the plugin */
    ei_logger_info("Getting function hello_world() from loaded memory plugin...");
UEUM_DISABLE_WIN32_PRAGMA_WARN(4152)
    if ((hello_world = mp_memory_plugin_get_function(plugin, "hello_world")) == NULL) {
UEUM_DISABLE_WIN32_PRAGMA_WARN_END()
        ei_stacktrace_push_msg("Failed to get hello_world function from loaded plugin of id", plugin_id);
        goto clean_up;
    }
    ei_logger_info("hello_world function retrieved");

    hello_world();

clean_up:
    if (plugin) {
        /* Unload the plugin */
        mp_memory_plugin_unload(plugin);
    }
#if defined(WITH_CRYPTO)
    uecm_crypto_metadata_destroy((uecm_crypto_metadata *)crypto_metadata);
    uecm_uninit();
#endif
    if (ei_stacktrace_is_filled()) {
        ei_logger_stacktrace("Error occurs with the following stacktrace:");
    }
    ei_uninit();
    return EXIT_SUCCESS;
}
