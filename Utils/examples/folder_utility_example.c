/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoUtilsModule.                             *
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

#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

#include <stdlib.h>

int main() {
    const char *directory_name, *file_name, *data;
    char *current_directory, **directories;
    int i, files_count;

    current_directory = NULL;
    directories = NULL;
    files_count = 0;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    directory_name = "hello";
    file_name = "hello/hello";
    data = "hello";

    uk_utils_logger_info("Getting current directory name...");
    if ((current_directory = uk_utils_get_current_dir()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to get current directory name");
        goto clean_up;
    }
    uk_utils_logger_info("The name of the current directory is: %s", current_directory);

    uk_utils_logger_info("Checking if the directory exists...");
    if (!uk_utils_is_dir_exists(directory_name)) {
        uk_utils_logger_info("%s directory doesn't exist. Creating...", directory_name);
        if (!uk_utils_create_folder(directory_name)) {
            uk_utils_stacktrace_push_msg("Failed to create folder %s", directory_name);
            goto clean_up;
        }
        uk_utils_logger_info("%s created.", directory_name);
        uk_utils_logger_info("Creating file %s with content %s...", file_name, data);
        if (!uk_utils_write_file(file_name, data)) {
            uk_utils_stacktrace_push_msg("Failed to write to file %s", file_name);
            goto clean_up;
        }
        uk_utils_logger_info("%s wrote.", file_name);
    } else {
        uk_utils_logger_info("The directory already %s exist and contains %d file(s)", directory_name, uk_utils_count_dir_files(directory_name, true));
        if ((directories = uk_utils_list_directory(directory_name, &files_count, true)) == NULL) {
            uk_utils_stacktrace_push_msg("Failed to list the content of the directory %s", directory_name);
            goto clean_up;
        }
        uk_utils_logger_info("The directory %s contains the following files:", directory_name);
        for (i = 0; i < files_count; i++) {
            printf("%s\n", directories[i]);
        }
        uk_utils_logger_info("Removing file %s...", file_name);
        remove(file_name);
        uk_utils_logger_info("Removing directory %s...", directory_name);
        remove(directory_name);
    }

clean_up:
    uk_utils_safe_free(current_directory);
    if (directories) {
        for (i = 0; i < files_count; i++) {
            uk_utils_safe_free(directories[i]);
        }
        free((void *)directories);
    }
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return 0;
}
