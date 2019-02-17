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

#include <stdlib.h>
#include <time.h>

/**
 * The purpose of this example is to show how to create
 * an empty plugin and save it to a specified target program.
 * The goal of create an empty plugin is that the target program
 * will update the content with a real plugin during it's running.
 */
int main(int argc, char **argv) {
    uk_mp_memory_plugin *plugin;
    int plugin_id;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    uk_utils_init();

    plugin = NULL;

    if (!uk_utils_is_file_exists(argv[1])) {
        uk_utils_stacktrace_push_msg("Specified plugin target file '%s' doesn't exist", argv[1]);
        goto clean_up;
    }

    srand((unsigned int)time(0));

    uk_utils_logger_info("Creating empty plugin...");
    if ((plugin = uk_mp_memory_plugin_create_empty()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create new plugin");
        goto clean_up;
    }
    uk_utils_logger_info("Empty plugin created");

    /**
    * save the plugin into the target path (exec or shared object). It returned the
    * corresponding id of the created plugin.
    */
    uk_utils_logger_info("Saving plugin to target file...");
    if ((plugin_id = uk_mp_memory_plugin_save(plugin, argv[1], NULL)) == -1) {
        uk_utils_stacktrace_push_msg("Failed to save new plugin to %s", argv[1]);
        goto clean_up;
    }

    uk_utils_logger_info("Succeed to save empty plugin with id %d", plugin_id);

clean_up:
    /* destroy only the object content and not the saved plugin */
    uk_mp_memory_plugin_destroy(plugin);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return EXIT_SUCCESS;
}
