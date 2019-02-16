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

#include <ueum/fileSystem/folder_utility.h>
#include <ueum/fileSystem/file_utility.h>
#include <ueum/string/string_utility.h>
#include <ueum/string/string_builder.h>
#include <ueum/string/string_split.h>
#include <ueum/container/string_vector.h>
#include <ueum/safe/safe_alloc.h>

#include <ei/ei.h>

#include <string.h>
#include <errno.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
    #include <direct.h>
#elif defined(__unix__)
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <dirent.h>
    #include <unistd.h>
#else
    #error "OS not supported"
#endif

bool ueum_is_dir_exists(const char *dir_name) {
#if defined(_WIN32) || defined(_WIN64)
    DWORD dw_attrib;
#else
    DIR *dir;
#endif

#if defined(_WIN32) || defined(_WIN64)
    dw_attrib = GetFileAttributesA(dir_name);
    if (dw_attrib != INVALID_FILE_ATTRIBUTES &&
        dw_attrib & FILE_ATTRIBUTE_DIRECTORY) {
        return true;
    }
#elif defined(__unix__)
    dir = opendir(dir_name);
    if (dir) {
        closedir(dir);
        return true;
    }
#else
    #error "OS not supported"
#endif

    return false;
}

int ueum_count_dir_files(const char *dir_name, bool recursively) {
    char path[2048];
    int files;

    ei_check_parameter_or_return(dir_name)

#if defined(_WIN32) || defined(_WIN64)
    WIN32_FIND_DATA fd_file;
    HANDLE file_handle;
#elif defined(__unix__)
    DIR *d;
    struct dirent *dir;
    char old_path[2048];
#else
    #error "OS not supported"
#endif

    files = 0;

#if defined(__unix__)
    strcpy(old_path, dir_name);

    d = opendir(dir_name);
    if (!d) {
        ei_stacktrace_push_errno()
        return -1;
    }

    while ((dir = readdir(d)) != NULL) {

        if (strcmp(dir->d_name, ".") != 0 &&
            strcmp(dir->d_name, "..") != 0) {

            memset(path, 0, sizeof(path));
            strcat(path, old_path);
            strcat(path, "/");
            strcat(path, dir->d_name);

            if (ueum_is_file_exists(path)) {
                files++;
            }
            else if (ueum_is_dir_exists(path) && recursively) {
                files += ueum_count_dir_files(path, true);
            }
        }
    }

    closedir(d);
#elif defined(_WIN32) || defined(_WIN64)
    file_handle = NULL;

    sprintf(path, "%s\\*.*", dir_name);

    if ((file_handle = FindFirstFile(path, &fd_file)) == INVALID_HANDLE_VALUE) {
        ei_stacktrace_push_msg("Failed to get first file")
        return -1;
    }

    do {
        /*
           Find first file will always return "."
           and ".." as the first two directories.
        */
        if (strcmp(fd_file.cFileName, ".") != 0 &&
           strcmp(fd_file.cFileName, "..") != 0) {

            sprintf(path, "%s\\%s", dir_name, fd_file.cFileName);

            if (ueum_is_file_exists(path)) {
                files++;
            }
            else if (fd_file.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY && recursively) {
                files += ueum_count_dir_files(path, true);
            }
        }
    }
    while(FindNextFile(file_handle, &fd_file)); /* Find the next file. */

    FindClose(&fd_file);
#else
    #error "OS not supported"
#endif

    return files;
}

char **ueum_list_directory(const char *dir_name, int *files, bool recursively) {
    char *temp_dir_char, **file_names, **new_folder_files, path[2048], slash;
    int i, j, files_count, new_folder_files_count;

    ei_check_parameter_or_return(dir_name)

    file_names = NULL;
    *files = 0;
    temp_dir_char = ueum_string_create_from(dir_name);

#if defined(__unix__)
    DIR *d;
    struct dirent *dir;
#elif defined(_WIN32) || defined(_WIN64)
    WIN32_FIND_DATA fd_file;
    HANDLE file_handle;
#else
    #error "OS not supported"
#endif

    slash = ' ';

#if defined(__unix__)
    slash = '/';
#elif defined(_WIN32) || defined(_WIN64)
    slash = '\\';
#else
    #error "OS not supported"
#endif

    if (ueum_last_char_is(temp_dir_char, slash)) {
        ueum_remove_last_char(temp_dir_char);
    }

    files_count = ueum_count_dir_files(temp_dir_char, recursively);

    if (files_count == -1) {
        ei_stacktrace_push_msg("Failed to count dir files")
        ueum_safe_free(temp_dir_char);
        return NULL;
    } else if (files_count == 0) {
        ueum_safe_free(temp_dir_char);
        return NULL;
    }

    i = 0;

#if defined(__unix__)
    d = opendir(temp_dir_char);
    if (!d) {
        ei_stacktrace_push_errno()
        ueum_safe_free(temp_dir_char);
        return NULL;
    }

    ueum_safe_alloc(file_names, char*, files_count)

    if (errno == ENOMEM || !file_names) {
        ueum_safe_free(file_names);
        ueum_safe_free(temp_dir_char);
        closedir(d);
        return NULL;
    }

    while ((dir = readdir(d)) != NULL) {
        strcpy(path, temp_dir_char);

        if (strcmp(dir->d_name, ".") != 0 &&
            strcmp(dir->d_name, "..") != 0) {
            strcat(path, "/");
            strcat(path, dir->d_name);


            if (ueum_is_file_exists(path)) {
                if (files_count + 1 > i) {
                    ueum_safe_realloc(file_names, char*, files_count, 1);
                }
                ueum_safe_alloc(file_names[i], char, strlen(path) + 1)
                strcpy(file_names[i], path);
                i++;
            }
            else if (ueum_is_dir_exists(path) && recursively) {
                new_folder_files = ueum_list_directory(path, &new_folder_files_count, true);
                if (new_folder_files) {
                    for (j = 0; j < new_folder_files_count; j++) {
                        if (new_folder_files[j]) {
                            if (files_count + 1 > i) {
                                ueum_safe_realloc(file_names, char*, files_count, 1);
                                /*files_count++;*/
                            }
                            ueum_safe_alloc(file_names[i], char, strlen(new_folder_files[j]) + 1)
                            strcpy(file_names[i], new_folder_files[j]);
                            i++;
                        }
                    }
                    for (j = 0; j < new_folder_files_count; j++) {
                        ueum_safe_free(new_folder_files[j]);
                    }
                    ueum_safe_free(new_folder_files);
                }
            }
        }
    }

    closedir(d);
#elif defined(_WIN32) || defined(_WIN64)
    file_handle = NULL;

    sprintf(path, "%s\\*.*", temp_dir_char);

    file_handle = FindFirstFile(path, &fd_file);
    if (file_handle == INVALID_HANDLE_VALUE) {
        ei_stacktrace_push_msg("Failed to get first file");
        ueum_safe_free(temp_dir_char);
        return NULL;
    }

    ueum_safe_alloc(file_names, char*, files_count)

    do {
        /*
           Find first file will always return "."
           and ".." as the first two directories.
        */
        if(strcmp(fd_file.cFileName, ".") != 0 &&
           strcmp(fd_file.cFileName, "..") != 0) {

            sprintf(path, "%s\\%s", temp_dir_char, fd_file.cFileName);

            if (ueum_is_file_exists(path)) {
                ueum_safe_alloc(file_names[i], char, strlen(path) + 1)
                strcpy(file_names[i], path);
                i++;
            }
            /* Is the entity a file or folder ? */
            else if(fd_file.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY && recursively) {
                new_folder_files = ueum_list_directory(path, &new_folder_files_count, true);
                if (new_folder_files) {
                    for (j = 0; j < new_folder_files_count; j++) {
                        ueum_safe_alloc(file_names[i], char, strlen(new_folder_files[j]) + 1)
                        strcpy(file_names[i], new_folder_files[j]);
                        i++;
                    }
                    for (j = 0; j < new_folder_files_count; j++) {
                        ueum_safe_free(new_folder_files[j]);
                    }
                    ueum_safe_free(new_folder_files);
                }
            }
        }
    }
    while(FindNextFile(file_handle, &fd_file)); /* Find the next file. */

    FindClose(&fd_file);
#else
    #error "OS not supported"
#endif

    ueum_safe_free(temp_dir_char);

    *files = files_count;

    return file_names;
}

char *ueum_get_current_dir() {
    char *dir;
#if defined(_WIN32) || defined(_WIN64)
    DWORD result;
    char *error_buffer;
#endif

    dir = NULL;

    ueum_safe_alloc(dir, char, 1024)

#if defined(__unix__)
    if (!getcwd(dir, 1024)) {
        ei_stacktrace_push_errno();
        goto failed;
    }
    return dir;
#elif defined(_WIN32) || defined(_WIN64)
    error_buffer = NULL;
    dir = NULL;
    ueum_safe_alloc(dir, char, MAX_PATH);
    result = GetModuleFileName(NULL, dir, MAX_PATH);
    if (result == ERROR_INSUFFICIENT_BUFFER) {
        ei_stacktrace_push_msg("Insufficient buffer size to copy current dir");
        goto failed;
    }
    if (GetLastError() != ERROR_SUCCESS) {
        ei_get_last_werror(error_buffer);
        ei_stacktrace_push_msg(error_buffer);
        ueum_safe_free(error_buffer);
        goto failed;
    }
    if (result < MAX_PATH) {
        ueum_safe_realloc(dir, char, MAX_PATH, result);
        return dir;
    }
#else
    #error "OS not supported"
#endif

failed:
    ueum_safe_free(dir)
    return NULL;
}

bool ueum_create_folder(const char *path_name) {
    bool result;
    ueum_string_builder *full_path;
    ueum_string_vector *paths;
    int i;

    if (ueum_is_dir_exists(path_name)) {
        ei_logger_warn("Folder at path '%s' already exists", path_name);
        return true;
    }

    result = false;
    full_path = ueum_string_builder_create();
    paths = ueum_string_vector_create_empty();
    ueum_string_split_append_one_delim(paths, path_name, "/");

    for (i = 0; i < ueum_string_vector_size(paths); i++) {
        ueum_string_builder_append_variadic(full_path, "%s/", ueum_string_vector_get(paths, i));
        if (!ueum_is_dir_exists(ueum_string_builder_get_data(full_path))) {
#if defined(__unix__)
            if (mkdir((const char *)ueum_string_builder_get_data(full_path), 0700) != 0) {
#elif defined(_WIN32) || defined(_WIN64)
            if (_mkdir((const char *)ueum_string_builder_get_data(full_path)) != 0) {
#endif
                ei_stacktrace_push_errno();
                goto clean_up;
            }
        }
    }

    result = true;

clean_up:
    ueum_string_builder_destroy(full_path);
    ueum_string_vector_destroy(paths);
    return result;
}
