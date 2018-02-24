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

#ifndef UNKNOWNECHO_COMPRESS_IMPL_H
#define UNKNOWNECHO_COMPRESS_IMPL_H

#include <unknownecho/bool.h>

#include <stdio.h>
#include <stddef.h>

bool ue_deflate_compress(unsigned char *plaintext, size_t plaintext_len, unsigned char **compressed_text, size_t *compressed_len);

bool ue_inflate_decompress(unsigned char *compressed_text, size_t compressed_len, unsigned char **decompressed_text, size_t decompressed_len);

bool ue_deflate_compress_file(FILE *source, FILE *dest, int level);

bool ue_inflate_decompress_file(FILE *source, FILE *dest);

#endif
