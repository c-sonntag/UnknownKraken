/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/fileSystem/folder_utility.h>
#include <unknownecho/fileSystem/file_utility.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/string/string_split.h>
#include <unknownecho/container/string_vector.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/system/alloc.h>

#include <string.h>
#include <errno.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#elif defined(__unix__)
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <dirent.h>
    #include <unistd.h>
#else
    #error "OS not supported"
#endif

bool ue_is_dir_exists(const char *file_name) {
    #if defined(_WIN32) || defined(_WIN64)
        DWORD dw_attrib;
    #else
        DIR *dir;
    #endif

    #if defined(_WIN32) || defined(_WIN64)
        dw_attrib = GetFileAttributesA(file_name);
        if (dw_attrib != INVALID_FILE_ATTRIBUTES &&
            dw_attrib & FILE_ATTRIBUTE_DIRECTORY) {
            return true;
        }
    #elif defined(__unix__)
        dir = opendir(file_name);
        if (dir) {
            closedir(dir);
            return true;
        }
    #else
        #error "OS not supported"
    #endif

    return false;
}

int ue_count_dir_files(const char *dir_name, bool recursively) {
    char path[2048];
    int files;

    ue_check_parameter_or_return(dir_name)

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
            ue_stacktrace_push_errno()
            return -1;
        }

        while ((dir = readdir(d)) != NULL) {

            if (strcmp(dir->d_name, ".") != 0 &&
                strcmp(dir->d_name, "..") != 0) {

                memset(path, 0, sizeof(path));
                strcat(path, old_path);
                strcat(path, "/");
                strcat(path, dir->d_name);

                if (ue_is_file_exists(path)) {
                    files++;
                }
                else if (ue_is_dir_exists(path) && recursively) {
                    files += ue_count_dir_files(path, true);
                }
            }
        }

        closedir(d);
    #elif defined(_WIN32) || defined(_WIN64)
        file_handle = NULL;

		sprintf(path, "%s\\*.*", dir_name);

        if((file_handle = FindFirstFile(path, &fd_file)) == INVALID_HANDLE_VALUE) {
            ue_stacktrace_push_msg("Failed to get first file")
            return -1;
        }

        do {
            /*
               Find first file will always return "."
               and ".." as the first two directories.
            */
            if(strcmp(fd_file.cFileName, ".") != 0 &&
               strcmp(fd_file.cFileName, "..") != 0) {

			    sprintf(path, "%s\\%s", dir_name, fd_file.cFileName);

                if (ue_is_file_exists(path)) {
                    files++;
                }
                else if (fd_file.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY && recursively) {
                    files += ue_count_dir_files(path, true);
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

char **ue_list_directory(char *dir_name, int *files, bool recursively) {
    char **file_names, **new_folder_files, path[2048], slash;
    int i, j, files_count, new_folder_files_count;

    ue_check_parameter_or_return(dir_name)

	file_names = NULL;
    *files = 0;

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

    if (ue_last_char_is(dir_name, slash)) {
        ue_remove_last_char(dir_name);
    }

    files_count = ue_count_dir_files(dir_name, recursively);

    if (files_count == -1) {
        ue_stacktrace_push_msg("Failed to count dir files")
        return NULL;
    } else if (files_count == 0) {
        return NULL;
    }

    i = 0;

    #if defined(__unix__)
        d = opendir(dir_name);
        if (!d) {
            ue_stacktrace_push_errno()
            return NULL;
        }

        ue_safe_alloc(file_names, char*, files_count)

        if (errno == ENOMEM || !file_names) {
            ue_safe_free(file_names);
            closedir(d);
            return NULL;
        }

        while ((dir = readdir(d)) != NULL) {
            strcpy(path, dir_name);

            if (strcmp(dir->d_name, ".") != 0 &&
                strcmp(dir->d_name, "..") != 0) {
                strcat(path, "/");
                strcat(path, dir->d_name);


                if (ue_is_file_exists(path)) {
                    if (files_count + 1 > i) {
                        ue_safe_realloc(file_names, char*, files_count, 1);
                    }
                    ue_safe_alloc(file_names[i], char, strlen(path) + 1)
                    strcpy(file_names[i], path);
                    i++;
                }
                else if (ue_is_dir_exists(path) && recursively) {
                    new_folder_files = ue_list_directory(path, &new_folder_files_count, true);
                    if (new_folder_files) {
                        for (j = 0; j < new_folder_files_count; j++) {
                            if (new_folder_files[j]) {
                                if (files_count + 1 > i) {
                                    ue_safe_realloc(file_names, char*, files_count, 1);
                                    /*files_count++;*/
                                }
                                ue_safe_alloc(file_names[i], char, strlen(new_folder_files[j]) + 1)
                                strcpy(file_names[i], new_folder_files[j]);
                                i++;
                            }
                        }
                        for (j = 0; j < new_folder_files_count; j++) {
                            ue_safe_free(new_folder_files[j]);
                        }
                        ue_safe_free(new_folder_files);
                    }
                }
            }
        }

        closedir(d);
    #elif defined(_WIN32) || defined(_WIN64)
        file_handle = NULL;

		sprintf(path, "%s\\*.*", dir_name);

        if (!(file_handle = FindFirstFile(path, &fd_file)) == INVALID_HANDLE_VALUE) {
            ue_stacktrace_push_msg("Failed to get first file");
            return NULL;
        }

        ue_safe_alloc(file_names, char*, files_count)

        do {
            /*
               Find first file will always return "."
               and ".." as the first two directories.
            */
            if(strcmp(fd_file.cFileName, ".") != 0 &&
               strcmp(fd_file.cFileName, "..") != 0) {

                sprintf(path, "%s\\%s", dir_name, fd_file.cFileName);

				if (ue_is_file_exists(path)) {
                    ue_safe_alloc(file_names[i], char, strlen(path) + 1)
					strcpy(file_names[i], path);
                    i++;
                }
                /* Is the entity a file or folder ? */
                else if(fd_file.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY && recursively) {
                    new_folder_files = ue_list_directory(path, &new_folder_files_count, true);
                    if (new_folder_files) {
                        for (j = 0; j < new_folder_files_count; j++) {
                            ue_safe_alloc(file_names[i], char, strlen(new_folder_files[j]) + 1)
                            strcpy(file_names[i], new_folder_files[j]);
                            i++;
                        }
                        for (j = 0; j < new_folder_files_count; j++) {
                            ue_safe_free(new_folder_files[j]);
                        }
                        ue_safe_free(new_folder_files);
                    }
                }
            }
        }
        while(FindNextFile(file_handle, &fd_file)); /* Find the next file. */

        FindClose(&fd_file);
    #else
        #error "OS not supported"
    #endif

    *files = files_count;

    return file_names;
}

char *ue_get_current_dir() {
    char *dir;

    ue_safe_alloc(dir, char, 1024)

    #if defined(__unix__)
        if (!getcwd(dir, 1024)) {
            ue_stacktrace_push_errno();
            goto failed;
        }
        return dir;
    #elif defined(_WIN32) || defined(_WIN64)
        ue_stacktrace_push_msg("Not implemented");
    #else
        #error "OS not supported"
    #endif

failed:
    ue_safe_free(dir)
    return NULL;
}

bool ue_create_folder(const char *path_name) {
    bool result;
#if defined(__unix__)
    ue_string_builder *full_path;
    ue_string_vector *paths;
    int i;
#endif

    if (ue_is_dir_exists(path_name)) {
        ue_logger_warn("Folder at path '%s' already exists", path_name);
        return true;
    }

    result = false;
#if defined(__unix__)
    full_path = ue_string_builder_create();
    paths = ue_string_vector_create_empty();
    ue_string_split_append_one_delim(paths, path_name, "/");
#endif

#if defined(__unix__)
    for (i = 0; i < ue_string_vector_size(paths); i++) {
        ue_string_builder_append_variadic(full_path, "%s/", ue_string_vector_get(paths, i));
        if (!ue_is_dir_exists(ue_string_builder_get_data(full_path))) {
            if (mkdir((const char *)ue_string_builder_get_data(full_path), 0700) != 0) {
                ue_stacktrace_push_errno();
                goto clean_up;
            }
        }
    }
#elif defined(_WIN32) || defined(_WIN64)
    // @todo _wmkdir, mkdir
    ue_stacktrace_push_msg("Not implemented");
#endif

    result = true;

clean_up:
#if defined(__unix__)
    ue_string_builder_destroy(full_path);
    ue_string_vector_destroy(paths);
#endif
    return result;
}
