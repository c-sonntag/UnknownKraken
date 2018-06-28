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

/**
 *  @file      folder_utility.h
 *  @brief     Utility functions relative to folder manipulations.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_FOLDER_UTILITY_H
#define UNKNOWNECHO_FOLDER_UTILITY_H

#include <unknownecho/bool.h>

bool ue_is_dir_exists(const char *file_name);

int ue_count_dir_files(const char *dir_name, bool recursively);

char **ue_list_directory(char *dir_name, int *files, bool recursively);

char *ue_get_current_dir();

bool ue_create_folder(const char *path_name);

#endif
