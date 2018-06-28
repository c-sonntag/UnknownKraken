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
 *  @file      byte_split.h
 *  @brief     Split bytes array into array of array of bytes.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_BYTE_SPLIT_H
#define UNKNOWNECHO_BYTE_SPLIT_H

#include <unknownecho/byte/byte_stream_struct.h>
#include <unknownecho/container/byte_vector.h>

#include <stddef.h>

/** 
 *  @todo clean up useless variables in the algorithm
 */
unsigned char **ue_byte_split(unsigned char *bytes, size_t bytes_len, unsigned char *delimiter, size_t delimiter_len, size_t *count, size_t **sizes);

bool ue_byte_split_append(ue_byte_vector *vector, unsigned char *bytes, size_t bytes_len, unsigned char *delimiter, size_t delimiter_len);

#endif
