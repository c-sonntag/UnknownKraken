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

#ifndef UnknownKrakenUtils_FOLDER_UTILITY_H
#define UnknownKrakenUtils_FOLDER_UTILITY_H

#include <uk/utils/compiler/bool.h>

bool uk_utils_is_dir_exists(const char *dir_name);

int uk_utils_count_dir_files(const char *dir_name, bool recursively);

char **uk_utils_list_directory(const char *dir_name, int *files, bool recursively);

char *uk_utils_get_current_dir();

bool uk_utils_create_folder(const char *path_name);

#endif
