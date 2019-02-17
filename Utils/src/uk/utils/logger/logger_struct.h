/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibErrorInterceptor.                                   *
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

/**
 *  @file      logger_struct.h
 *  @brief     Logger structure that contains the context of the log trace.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @see       logger.h
 */

#ifndef UnknownKrakenUtils_LOGGER_STRUCT_H
#define UnknownKrakenUtils_LOGGER_STRUCT_H

#include <uk/utils/compiler/bool.h>
#include <uk/utils/thread/thread_mutex.h>

#include <stdio.h>

typedef enum {
    UnknownKrakenUtils_LOG_TRACE = 0,
    UnknownKrakenUtils_LOG_DEBUG,
    UnknownKrakenUtils_LOG_INFO,
    UnknownKrakenUtils_LOG_WARNING,
    UnknownKrakenUtils_LOG_ERROR,
    UnknownKrakenUtils_LOG_FATAL
} uk_utils_logger_type;

typedef struct {
    int print_level, file_level;
    bool colored;
    bool details;
    bool padding;
    bool message_color_as_level_color;
    FILE *fp;
    uk_utils_thread_mutex *mutex;
    char **level_colors;
    char *message_color;
    char **level_names;
} uk_utils_logger;

#endif
