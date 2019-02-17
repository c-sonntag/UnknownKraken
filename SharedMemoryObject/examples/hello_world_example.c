/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibSharedMemoryObject.                                 *
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

#include <uk/smo/smo.h>
#include <uk/smo/api/smo_handle.h>
#include <uk/utils/ueum.h>

#include <uk/utils/ei.h>

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>

/**
* @brief Get the file size object
*
* @param fd  file descriptor
* @return ssize_t  size of the file
*/
static ssize_t get_file_size(FILE *fd) {
    ssize_t file_size;

    file_size = -1;

    if (!fd) {
        return -1;
    }

    fseek(fd, 0, SEEK_END);
    file_size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    return file_size;
}

static unsigned char *read_shared_library(const char *path, ssize_t *size) {
    FILE *fd;
    unsigned char *buf;
    ssize_t temp_size;

    fd = NULL;
    buf = NULL;

    /* Open the shared library from the disk */
    if (!(fd = fopen(path, "rb"))) {
        uk_utils_stacktrace_push_errno();
        return NULL;
    }

    /* Get the size of the file */
    if ((temp_size = get_file_size(fd)) == -1) {
        uk_utils_stacktrace_push_errno();
        if (fclose(fd) != 0) {
            uk_utils_logger_warn("Failed to close file descriptor with error message: '%s'", strerror(errno));
        }
        return NULL;
    }

    /* Alloc the correct size for the buffer */
    uk_utils_safe_alloc(buf, unsigned char, temp_size);

    if (!fread(buf, temp_size, 1, fd)) {
        uk_utils_stacktrace_push_errno();
        if (fclose(fd) != 0) {
            uk_utils_logger_warn("Failed to close file descriptor with error message: '%s'", strerror(errno));
        }
        return NULL;
    }

    *size = temp_size;

    if (fclose(fd) != 0) {
        uk_utils_logger_warn("Failed to close file descriptor with error message: '%s'", strerror(errno));
    }

    return buf;
}

int main(int argc, char **argv) {
    unsigned char *buf;
    ssize_t size;
    uk_smo_handle *handle;
    typedef void(*hello_world_func)(void);
    hello_world_func hello_world;

    if (argc != 2) {
        fprintf(stderr, "Usage: ./%s <shared_object_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    size = -1;
    buf = NULL;
    handle = NULL;

    /* Initialize LibErrorInterceptor for error handling */
    if (!uk_utils_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibErrorInterceptor\n");
        exit(EXIT_FAILURE);
    }

    if (!(buf = read_shared_library(argv[1], &size))) {
        uk_utils_stacktrace_push_msg("Failed to read shared library from disk");
        goto clean_up;
    }

    if (!(handle = uk_smo_open("id", buf, size))) {
        uk_utils_stacktrace_push_msg("Failed to open sharfed memory object from specified buffer");
        goto clean_up;
    }

#if defined(__GNUC__)
    _Pragma("GCC diagnostic push");
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"");
#endif
    if (!(hello_world = uk_smo_get_function(handle, "hello_world"))) {
#if defined(__GNUC__)
    _Pragma("GCC diagnostic pop");
#endif
        uk_utils_stacktrace_push_msg("Failed to get symbol of function hello");
        goto clean_up;
    }

    hello_world();

clean_up:
    uk_smo_close(handle);
    uk_utils_safe_free(buf);
    /* Check if an error was recorded */
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_stacktrace("An error occurred with the following stacktrace :");
        uk_utils_stacktrace_print();
    }
    /* Uninit the error handling library */
    uk_utils_uninit();
    return EXIT_SUCCESS;
}
