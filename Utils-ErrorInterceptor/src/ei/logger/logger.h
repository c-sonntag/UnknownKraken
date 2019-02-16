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

#ifndef ERRORINTERCEPTOR_LOGGER_H
#define ERRORINTERCEPTOR_LOGGER_H

#include <ei/bool.h>
#include <ei/logger/logger_struct.h>
#include <ei/logger/logger_manager.h>
#include <ei/stacktrace/stacktrace_struct.h>
#include <ei/thread/thread_storage.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

ei_logger *ei_logger_create();

void ei_logger_destroy(ei_logger *log);

void ei_logger_set_fp(ei_logger *log, FILE *fp);

void ei_logger_set_file_level(ei_logger *log, int level);

void ei_logger_set_print_level(ei_logger *log, int level);

int ei_logger_get_print_level(ei_logger *log);

int ei_logger_get_file_level(ei_logger *log);

void ei_logger_set_colored(ei_logger *log, bool enable);

void ei_logger_set_details(ei_logger *log, bool enable);

void ei_logger_set_padding(ei_logger *log, bool enable);

void ei_logger_set_message_color(ei_logger *log, const char *color);

void ei_logger_set_message_color_as_level_color(ei_logger *log, bool enable);

void ei_logger_set_symbol_levels(ei_logger *log, bool enable);

#define ei_logger_use_symbol_levels() ei_logger_set_symbol_levels(ei_logger_manager_get_logger(), true)

#define ei_logger_use_message_color_as_level_color() ei_logger_set_message_color_as_level_color(ei_logger_manager_get_logger(), true)

bool ei_logger_record(ei_logger *log, int level, const char *file, int line, const char *fmt, ...);

bool ei_logger_record_stacktrace(ei_logger *log, ei_stacktrace *stacktrace, const char *message, const char *file, int line);

#define ei_logger_stacktrace(message) ei_logger_record_stacktrace(ei_logger_manager_get_logger(), ei_thread_storage_get_stacktrace(), (const char *)message, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__)

#define ei_logger_trace(...) ei_logger_record(ei_logger_manager_get_logger(), ERRORINTERCEPTOR_LOG_TRACE, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

#define ei_logger_debug(...) ei_logger_record(ei_logger_manager_get_logger(), ERRORINTERCEPTOR_LOG_DEBUG, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

#define ei_logger_info(...) ei_logger_record(ei_logger_manager_get_logger(), ERRORINTERCEPTOR_LOG_INFO, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

#define ei_logger_warn(...) ei_logger_record(ei_logger_manager_get_logger(), ERRORINTERCEPTOR_LOG_WARNING,  (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

#define ei_logger_error(...) ei_logger_record(ei_logger_manager_get_logger(), ERRORINTERCEPTOR_LOG_ERROR, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

#define ei_logger_fatal(...) ei_logger_record(ei_logger_manager_get_logger(), ERRORINTERCEPTOR_LOG_FATAL, (const char *)(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), __LINE__, __VA_ARGS__)

FILE *ei_logger_get_fp(ei_logger *log);

#endif
