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
 *  @file      compress.h
 *  @brief     Compress/decompress byte or file.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_COMPRESS_H
#define UNKNOWNECHO_COMPRESS_H

#include <unknownecho/bool.h>

#include <stddef.h>
#include <stdio.h>

unsigned char *ue_compress_buf(unsigned char *plaintext, size_t plaintext_size, size_t *compressed_size);

unsigned char *ue_decompress_buf(unsigned char *compressed_text, size_t compressed_text_size, size_t plaintext_size);

bool ue_compress_file(FILE *source, FILE *dest);

bool ue_decompress_file(FILE *source, FILE *dest);

#endif
