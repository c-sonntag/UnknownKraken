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
 *  @file      string_split.h
 *  @brief     String split funcntions.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_STRING_SPLIT_H
#define UNKNOWNECHO_STRING_SPLIT_H

#include <unknownecho/bool.h>
#include <unknownecho/container/string_vector.h>

ue_string_vector *ue_string_split(char *string, char *delimiter);

bool ue_string_split_append(ue_string_vector *v, char *string, char *delimiter);

bool ue_string_split_append_one_delim(ue_string_vector *v, const char *string, const char *delimiter);

#endif
