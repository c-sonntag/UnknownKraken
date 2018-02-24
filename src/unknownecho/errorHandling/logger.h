/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * Inspired by log.c of rxi on Github : https://github.com/rxi/log.c           *
 *                                                                             *
 * Copyright (c) 2017 rxi                                                      *
 *                                                                             *
 * This library is free software; you can redistribute it and/or modify it     *
 * under the terms of the MIT license. See `log.c` for details.                *
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
 *  @file      logger.h
 *  @brief     Logger module handle different types of log message.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       logger_struct.h
 */

#ifndef UNKNOWNECHO_LOGGER_H
#define UNKNOWNECHO_LOGGER_H

#include <unknownecho/bool.h>
#include <unknownecho/errorHandling/logger_struct.h>
#include <unknownecho/errorHandling/logger_manager.h>

#include <stdio.h>
#include <stdarg.h>

ue_logger *ue_logger_create();

void ue_logger_destroy(ue_logger *log);

void ue_logger_set_fp(ue_logger *log, FILE *fp);

void ue_logger_set_level(ue_logger *log, int level);

int ue_logger_get_level(ue_logger *log);

void ue_logger_set_quiet(ue_logger *log, bool enable);

void ue_logger_set_colored(ue_logger *log, bool enable);

void ue_logger_set_details(ue_logger *log, bool enable);

bool ue_logger_record(ue_logger *log, int level, const char *file, int line, const char *fmt, ...);

#define ue_logger_trace(...) ue_logger_record(ue_logger_manager_get_logger(), LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)

#define ue_logger_debug(...) ue_logger_record(ue_logger_manager_get_logger(), LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#define ue_logger_info(...) ue_logger_record(ue_logger_manager_get_logger(), LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)

#define ue_logger_warn(...) ue_logger_record(ue_logger_manager_get_logger(), LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)

#define ue_logger_error(...) ue_logger_record(ue_logger_manager_get_logger(), LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)

#define ue_logger_fatal(...) ue_logger_record(ue_logger_manager_get_logger(), LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

FILE *ue_logger_get_fp(ue_logger *log);

#endif
