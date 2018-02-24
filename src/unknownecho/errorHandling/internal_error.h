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
 *  @file      internal_error.h
 *  @brief     Internal error provides a set of common errors.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_INTERNAL_ERROR_H
#define UNKNOWNECHO_INTERNAL_ERROR_H

#include <unknownecho/errorHandling/error.h>

#include <stdio.h>

typedef enum {
	UNKNOWNECHO_SUCCESS,
	UNKNOWNECHO_NO_SUCH_MEMORY,
	UNKNOWNECHO_FILE_NOT_FOUND,
    UNKNOWNECHO_INVALID_PARAMETER,
    UNKNOWNECHO_NO_INTERNET_CONNECTION,
	UNKNOWNECHO_UNKNOWN_ERROR
} ue_internal_error_type;

char *ue_internal_error_get_description(ue_internal_error_type type);

char *ue_internal_error_to_string(ue_error *e);

void ue_internal_error_print(ue_error *e, FILE *out);

#endif
