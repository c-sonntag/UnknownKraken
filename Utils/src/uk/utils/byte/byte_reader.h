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

#ifndef UnknownKrakenUtils_BYTE_READER_H
#define UnknownKrakenUtils_BYTE_READER_H

#include <uk/utils/compiler/bool.h>
#include <uk/utils/byte/byte_stream_struct.h>

#include <stddef.h>

bool uk_utils_byte_read_is_int(uk_utils_byte_stream *stream, int position, int n);

/**
 *  @brief      Read the next int of the bytes stream.
 *  @param[in]  stream of bytes
 *  @param[out] n int reference
 *  @return     true if the int reference is filled
 *              otherwise, an error is added to the stacktrace
 *              and false is returned.
 *  @pre        The stream must be initialized and filled.
 */
bool uk_utils_byte_read_next_int(uk_utils_byte_stream *stream, int *n);

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
bool uk_utils_byte_read_next_bytes(uk_utils_byte_stream *stream, unsigned char **bytes, size_t len);

/**
 * @brief uk_utils_byte_read_next_stream
 * @param stream
 * @param new_stream  needs to be allocated before
 * @return
 */
bool uk_utils_byte_read_next_stream(uk_utils_byte_stream *stream, uk_utils_byte_stream *new_stream);

bool uk_utils_byte_read_next_string(uk_utils_byte_stream *stream, const char **string, size_t len);

//bool uk_utils_byte_read_remaining_bytes(uk_utils_byte_stream *stream, unsigned char **bytes, size_t *len);

#endif
