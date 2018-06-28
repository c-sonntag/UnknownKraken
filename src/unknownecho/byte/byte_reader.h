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
 *  @file      byte_reader.h
 *  @brief     Read next value in a ue_byte_stream.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       ue_byte_stream
 *  @todo      read other types, like size_t, long, char *, etc.
 *
 *  <b>Example</b>
 *  @code
 *  int n;
 *  unsigned char *bytes;
 *  if (!ue_byte_read_next_int(stream, &n)) {
 *     // error handling>
 *  }
 *  if (!ue_byte_read_next_bytes(stream, &bytes, (size_t)n)) {
 *     // error handling>
 *  }
 *  @endcode
 */

#ifndef UNKNOWNECHO_BYTE_READER_H
#define UNKNOWNECHO_BYTE_READER_H

#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_stream_struct.h>

#include <stddef.h>

bool ue_byte_read_is_int(ue_byte_stream *stream, int position, int n);

/**
 *  @brief      Read the next int of the bytes stream.
 *  @param[in]  stream of bytes
 *  @param[out] n int reference
 *  @return     true if the int reference is filled
 *              otherwise, an error is added to the stacktrace
 *              and false is returned.
 *  @pre        The stream must be initialized and filled.
 */
bool ue_byte_read_next_int(ue_byte_stream *stream, int *n);

/**
 *  @brief      Read the next bytes of the bytes stream.
 *  @param[in]  stream of bytes
 *  @param[out] bytes reference of bytes
 *  @param[in]  len to read
 *  @return     true if the bytes reference is allocated and filled
 *              otherwise, an error is added to the stacktrace
 *              and false is returned.
 *  @pre        The stream must be initialized and filled.
 */
bool ue_byte_read_next_bytes(ue_byte_stream *stream, unsigned char **bytes, size_t len);

/**
 * @brief ue_byte_read_next_stream
 * @param stream
 * @param new_stream  needs to be allocated before
 * @return
 */
bool ue_byte_read_next_stream(ue_byte_stream *stream, ue_byte_stream *new_stream);

bool ue_byte_read_next_string(ue_byte_stream *stream, const char **string, size_t len);

//bool ue_byte_read_remaining_bytes(ue_byte_stream *stream, unsigned char **bytes, size_t *len);

#endif
