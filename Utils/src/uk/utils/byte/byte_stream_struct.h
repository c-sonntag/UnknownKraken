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

#ifndef UnknownKrakenUtils_BYTE_STREAM_STRUCT_H
#define UnknownKrakenUtils_BYTE_STREAM_STRUCT_H

#include <stdint.h>

/**
 * @brief   stream of bytes
 *
 * The max size of the stream is position <= size <= limit.
 * The position is incremented when a data is read from the stream,
 * or wrote into.
 * The size is incremented and the field bytes in expand when the
 * the size isn't enough to write.
 * The is fixed at the creation of the stream, or 1024 by default.
 */
typedef struct {
    unsigned char *bytes; /** bytes of the stream */
    uint64_t limit; /** limit of the bytes field */
    uint64_t position; /** current position of the bytes field */
    uint64_t size; /** current max size of the stream */
} uk_utils_byte_stream;

#endif
