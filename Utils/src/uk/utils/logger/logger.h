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
 *  @file      logger.h
 *  @brief     Logger module handle different types of log message.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @see       logger_struct.h
 */

#ifndef UnknownKrakenUtils_LOGGER_H
#define UnknownKrakenUtils_LOGGER_H

#include <uk/utils/compiler/bool.h>
#include <uk/utils/logger/logger_struct.h>
#include <uk/utils/logger/logger_manager.h>
#include <uk/utils/stacktrace/stacktrace_struct.h>
#include <uk/utils/thread/thread_storage.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

uk_utils_logger *uk_utils_logger_create();

void uk_utils_logger_destroy(uk_utils_logger *log);

void uk_utils_logger_set_fp(uk_utils_logger *log, FILE *fp);

void uk_utils_logger_set_file_level(uk_utils_logger *log, int level);

void uk_utils_logger_set_print_level(uk_utils_logger *log, int level);

int uk_utils_logger_get_print_level(uk_utils_logger *log);

int uk_utils_logger_get_file_level(uk_utils_logger *log);

void uk_utils_logger_set_colored(uk_utils_logger *log, bool enable);

void uk_utils_logger_set_details(uk_utils_logger *log, bool enable);

void uk_utils_logger_set_padding(uk_utils_logger *log, bool enable);

void uk_utils_logger_set_message_color(uk_utils_logger *log, const char *color);

void uk_utils_logger_set_message_color_as_level_color(uk_utils_logger *log, bool enable);

void uk_utils_logger_set_symbol_levels(uk_utils_logger *log, bool enable);

#define uk_utils_logger_use_symbol_levels() uk_utils_logger_set_symbol_levels(uk_utils_logger_manager_get_logger(), true)

#define uk_utils_logger_use_message_color_as_level_color() uk_utils_logger_set_message_color_as_level_color(uk_utils_logger_manager_get_logger(), true)

bool uk_utils_logger_record(uk_utils_logger *log, int level, const char *file, int line, const char *fmt, ...);

bool uk_utils_logger_record_stacktrace(uk_utils_logger *log, uk_utils_stacktrace *stacktrace, const char *message, const char *file, int line);

#define uk_utils_logger_stacktrace(message) uk_utils_logger_record_stacktrace(uk_utils_logger_manager_get_logger(), uk_utils_thread_storage_get_stacktrace(), (const char *)message, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__)

#define uk_utils_logger_trace(...) uk_utils_logger_record(uk_utils_logger_manager_get_logger(), UnknownKrakenUtils_LOG_TRACE, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

#define uk_utils_logger_debug(...) uk_utils_logger_record(uk_utils_logger_manager_get_logger(), UnknownKrakenUtils_LOG_DEBUG, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

#define uk_utils_logger_info(...) uk_utils_logger_record(uk_utils_logger_manager_get_logger(), UnknownKrakenUtils_LOG_INFO, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

#define uk_utils_logger_warn(...) uk_utils_logger_record(uk_utils_logger_manager_get_logger(), UnknownKrakenUtils_LOG_WARNING,  (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

#define uk_utils_logger_error(...) uk_utils_logger_record(uk_utils_logger_manager_get_logger(), UnknownKrakenUtils_LOG_ERROR, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

#define uk_utils_logger_fatal(...) uk_utils_logger_record(uk_utils_logger_manager_get_logger(), UnknownKrakenUtils_LOG_FATAL, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

FILE *uk_utils_logger_get_fp(uk_utils_logger *log);

#endif
