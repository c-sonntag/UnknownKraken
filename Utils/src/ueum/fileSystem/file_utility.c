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

#include <ueum/fileSystem/file_utility.h>
#include <ei/ei.h>
#include <ueum/safe/safe_alloc.h>

#if defined(__unix__)
    #include <sys/types.h>
    #include <sys/stat.h>
#elif defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#else
    #error "OS not supported"
#endif

#include <string.h>

bool ueum_is_file_exists(const char *file_name) {
#if defined(__unix__)
    struct stat st;
#elif defined(_WIN32) || defined(_WIN64)
    DWORD dw_attrib;
#else
    #error "OS not supported"
#endif

#if defined(__unix__)
    if (stat(file_name, &st) == 0) {
        return S_ISREG(st.st_mode);
    }
    return false;
#elif defined(_WIN32) || defined(_WIN64)
    dw_attrib = GetFileAttributesA(file_name);
    if (dw_attrib != INVALID_FILE_ATTRIBUTES &&
        dw_attrib != FILE_ATTRIBUTE_DIRECTORY) {
        return true;
    }
#endif

    return false;
}

ssize_t ueum_get_file_size(FILE *fd) {
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

char *ueum_read_file(const char *file_name) {
    char *out;
    FILE *fd;
    size_t file_size;

    fd = NULL;
    out = NULL;

    ei_check_parameter_or_return(file_name);

    if ((fd = fopen(file_name, "r")) == NULL) {
        ei_stacktrace_push_errno();
        return NULL;
    }

    if ((file_size = ueum_get_file_size(fd)) <= 0) {
        ei_stacktrace_push_msg("Empty file");
        goto clean_up;
    }

    ueum_safe_alloc_or_goto(out, char, file_size + 1, clean_up);

    if (fread(out, file_size, 1, fd) == 0) {
        ueum_safe_free(out);
        ei_stacktrace_push_errno();
    }

clean_up:
    fclose(fd);

    return out;
}

bool ueum_write_file(const char *file_name, const char *data) {
    FILE *fd;
    bool state;

    state = false;

    ei_check_parameter_or_return(file_name);
    ei_check_parameter_or_return(data);

    if ((fd = fopen(file_name, "w")) == NULL) {
        ei_stacktrace_push_errno();
        return false;
    }

    if (fwrite(data, strlen(data), 1, fd) != 1) {
        ei_stacktrace_push_errno();
        goto clean_up;
    }

    state = true;

clean_up:
    fclose(fd);

    return state;
}

unsigned char *ueum_read_binary_file(const char *file_name, size_t *size) {
    unsigned char *out;
    FILE *fd;
    size_t file_size;

    out = NULL;

    ei_check_parameter_or_return(file_name);

    if ((fd = fopen(file_name, "rb")) == NULL) {
        ei_stacktrace_push_errno();
        return NULL;
    }

    if ((file_size = ueum_get_file_size(fd)) <= 0) {
        ei_stacktrace_push_msg("Empty file");
        goto clean_up;
    }

    ueum_safe_alloc_or_goto(out, unsigned char, file_size, clean_up);

    if (fread(out, file_size, 1, fd) == 0) {
        ueum_safe_free(out);
        ei_stacktrace_push_errno();
    }

    *size = file_size;

clean_up:
    fclose(fd);

    return out;
}

bool ueum_write_binary_file(const char *file_name, unsigned char *data, size_t size) {
    FILE *fd;
    bool state;

    state = false;

    ei_check_parameter_or_return(file_name);
    ei_check_parameter_or_return(data);

    if ((fd = fopen(file_name, "wb")) == NULL) {
        ei_stacktrace_push_errno();
        return false;
    }

    if (fwrite(data, size, 1, fd) != 1) {
        ei_stacktrace_push_errno();
        goto clean_up;
    }

    state = true;

clean_up:
    fclose(fd);

    return state;
}
