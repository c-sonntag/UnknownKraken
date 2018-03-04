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
 *  @file      logger_struct.h
 *  @brief     Logger structure that contains the context of the log trace.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       logger.h
 */

#ifndef UNKNOWNECHO_LOGGER_STRUCT_H
#define UNKNOWNECHO_LOGGER_STRUCT_H

#include <unknownecho/bool.h>
#include <unknownecho/thread/thread_mutex.h>

#include <stdio.h>

typedef enum {
    LOG_TRACE = 0,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
} ue_logger_type;

typedef struct {
    int print_level, file_level;
    bool quiet;
    bool colored;
    bool details;
    FILE *fp;
    ue_thread_mutex *mutex;
} ue_logger;

#endif
