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
#include <uk/utils/ei.h>

#include <stdlib.h>
#include <time.h>
#include <stdio.h>

/**
 * The purpose of this example is to show how to release
 * a memory plugin. The goal is to back to the same state as an 
 * empty plugin (see: create_empty_plugin_example).
 * After the plugin is released, we can still update it with a new
 * content.
 * DOESN'T WORK FOR NOW
 */
int main(int argc, char **argv) {
    uk_mp_memory_plugin *plugin;
    int plugin_id;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <plugin_id>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    srand((unsigned int)time(0));
    plugin = NULL;
    plugin_id = atoi(argv[1]);
    uk_utils_init();

    /* Load plugin from id */
    uk_utils_logger_info("Loading memory plugin from id %d", plugin_id);
    if ((plugin = uk_mp_memory_plugin_load(plugin_id, NULL)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to load plugin with id %d", plugin_id);
        goto clean_up;
    }
    uk_utils_logger_info("Memory plugin loaded");

    uk_utils_logger_info("Releasing memory plugin...");
    if (!uk_mp_memory_plugin_release(plugin)) {
        uk_utils_stacktrace_push_msg("Failed to release our plugin");
        goto clean_up;
    }
    uk_utils_logger_info("Memory plugin released");

clean_up:
    uk_mp_memory_plugin_destroy(plugin);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return EXIT_SUCCESS;
}
