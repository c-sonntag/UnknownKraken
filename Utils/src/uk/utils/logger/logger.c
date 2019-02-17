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

/*
 * Inspired by log.c of rxi on Github : https://github.com/rxi/log.c
 *
 * Copyright (c) 2017 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See `log.c` for details.
 */

#include <uk/utils/logger/logger.h>
#include <uk/utils/string/string_utility.h>
#include <uk/utils/stacktrace/stacktrace.h>
#include <uk/utils/check_parameter.h>
#include <uk/utils/safe/safe_alloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LEVEL_NAME_MAX_SIZE  7

#if defined(__unix__)

#define UnknownKrakenUtils_SKY_BLUE_COLOR                   "\x1b[94m"
#define UnknownKrakenUtils_TURQUOISE_BLUE_COLOR             "\x1b[36m"
#define UnknownKrakenUtils_GREEN_COLOR                      "\x1b[32m"
#define UnknownKrakenUtils_YELLOW_COLOR                     "\x1b[33m"
#define UnknownKrakenUtils_RED_COLOR                        "\x1b[31m"
#define UnknownKrakenUtils_PURPLE_COLOR                     "\x1b[35m"
#define UnknownKrakenUtils_GRAY_COLOR                       "\x1b[90m"
#define UnknownKrakenUtils_WHITE_COLOR                      "\x1b[0m"

#elif defined(_WIN32) || defined(_WIN64)

#define UnknownKrakenUtils_SKY_BLUE_COLOR                   ""
#define UnknownKrakenUtils_TURQUOISE_BLUE_COLOR             ""
#define UnknownKrakenUtils_GREEN_COLOR                      ""
#define UnknownKrakenUtils_YELLOW_COLOR                     ""
#define UnknownKrakenUtils_RED_COLOR                        ""
#define UnknownKrakenUtils_PURPLE_COLOR                     ""
#define UnknownKrakenUtils_GRAY_COLOR                       ""
#define UnknownKrakenUtils_WHITE_COLOR                      ""

#endif

static const char *level_status[] = {
    "TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "FATAL"
};

static const char *level_symbols[] = {
    "~", "~", "+", "-", "-", "-"
};

uk_utils_logger *uk_utils_logger_create() {
    uk_utils_logger *log;

    log = NULL;

    uk_utils_safe_alloc(log, uk_utils_logger, 1);
    log->print_level = 0;
    log->file_level = 0;
    log->fp = NULL;
    log->mutex = uk_utils_thread_mutex_create();
    log->colored = true;
    log->details = true;
    log->padding = false;
    log->message_color_as_level_color = false;
    log->level_names = (char **)level_status;

    uk_utils_safe_alloc(log->level_colors, char *, 6);
    log->level_colors[UnknownKrakenUtils_LOG_TRACE] = uk_utils_string_create_from(UnknownKrakenUtils_SKY_BLUE_COLOR);
    log->level_colors[UnknownKrakenUtils_LOG_DEBUG] = uk_utils_string_create_from(UnknownKrakenUtils_TURQUOISE_BLUE_COLOR);
    log->level_colors[UnknownKrakenUtils_LOG_INFO] = uk_utils_string_create_from(UnknownKrakenUtils_GREEN_COLOR);
    log->level_colors[UnknownKrakenUtils_LOG_WARNING] = uk_utils_string_create_from(UnknownKrakenUtils_YELLOW_COLOR);
    log->level_colors[UnknownKrakenUtils_LOG_ERROR] = uk_utils_string_create_from(UnknownKrakenUtils_RED_COLOR);
    log->level_colors[UnknownKrakenUtils_LOG_FATAL] = uk_utils_string_create_from(UnknownKrakenUtils_PURPLE_COLOR);

    log->message_color = uk_utils_string_create_from(UnknownKrakenUtils_WHITE_COLOR);

    return log;
}

void uk_utils_logger_destroy(uk_utils_logger *log) {
    if (log) {
        uk_utils_thread_mutex_destroy(log->mutex);
        uk_utils_safe_free(log->level_colors[UnknownKrakenUtils_LOG_TRACE]);
        uk_utils_safe_free(log->level_colors[UnknownKrakenUtils_LOG_DEBUG]);
        uk_utils_safe_free(log->level_colors[UnknownKrakenUtils_LOG_INFO]);
        uk_utils_safe_free(log->level_colors[UnknownKrakenUtils_LOG_WARNING]);
        uk_utils_safe_free(log->level_colors[UnknownKrakenUtils_LOG_ERROR]);
        uk_utils_safe_free(log->level_colors[UnknownKrakenUtils_LOG_FATAL]);
        uk_utils_safe_free(log->level_colors);
        uk_utils_safe_free(log->message_color);
        uk_utils_safe_free(log);
    }
}

void uk_utils_logger_set_fp(uk_utils_logger *log, FILE *fp) {
    log->fp = fp;
}

void uk_utils_logger_set_file_level(uk_utils_logger *log, int level) {
    log->file_level = level;
}

void uk_utils_logger_set_print_level(uk_utils_logger *log, int level) {
    log->print_level = level;
}

int uk_utils_logger_get_print_level(uk_utils_logger *log) {
    return  log->print_level;
}

int uk_utils_logger_get_file_level(uk_utils_logger *log) {
    return  log->file_level;
}

void uk_utils_logger_set_colored(uk_utils_logger *log, bool enable) {
    log->colored = enable;
}

void uk_utils_logger_set_details(uk_utils_logger *log, bool enable) {
    log->details = enable;
}

void uk_utils_logger_set_padding(uk_utils_logger *log, bool enable) {
    log->padding = enable;
}

void uk_utils_logger_set_message_color(uk_utils_logger *log, const char *color) {
    uk_utils_safe_free(log->message_color);
    log->message_color = uk_utils_string_create_from(color);
}

void uk_utils_logger_set_message_color_as_level_color(uk_utils_logger *log, bool enable) {
    log->message_color_as_level_color = enable;
}

void uk_utils_logger_set_symbol_levels(uk_utils_logger *log, bool enable) {
    if (enable) {
        log->level_names = (char **)level_symbols;
    } else {
        log->level_names = (char **)level_status;
    }
}

bool uk_utils_logger_record(uk_utils_logger *log, int level, const char *file, int line, const char *fmt, ...) {
    time_t rawtime;
    struct tm *timeinfo;
    va_list args;
    char *date_time;
    unsigned short int padding_size;
    char *message_color;

    if (!log) {
        return false;
    }

    /* Acquire lock */
    uk_utils_thread_mutex_lock(log->mutex);

    /* Get current time */
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    date_time = asctime(timeinfo);
    date_time[strlen(date_time) - 1] = '\0';

    if (log->padding) {
        padding_size = LEVEL_NAME_MAX_SIZE - strlen(log->level_names[level]);
    } else {
        padding_size = 0;
    }

    if (log->message_color_as_level_color) {
        message_color = log->level_colors[level];
    } else {
        message_color = log->message_color;
    }

    /* Log to stdout */
    if (level >= log->print_level) {
        if (log->colored) {
            if (log->details) {
                fprintf(stdout, "%s[%s] [%s:%d] ", log->level_colors[level], date_time, file, line);
            }

            fprintf(stdout, "%s[%s]%*s%s %s", log->level_colors[level], log->level_names[level], padding_size,
                "", UnknownKrakenUtils_WHITE_COLOR, message_color);
        } else {
            if (log->details) {
                fprintf(stdout, "[%s] [%s:%d] ", date_time, file, line);
            }

            fprintf(stdout, "[%s]%*s ", log->level_names[level], padding_size, "");
        }

        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
        if (log->colored) {
            fprintf(stdout, "%s", UnknownKrakenUtils_WHITE_COLOR);
        }
        fprintf(stdout, "\n");
    }

    /* Log to file */
    if (log->fp != NULL && level >= log->file_level) {
        if (log->details) {
            fprintf(log->fp, "[%s] [%s:%d] ", date_time, file, line);
        }

        fprintf(log->fp, "[%s]%*s ", log->level_names[level], padding_size, "");

        va_start(args, fmt);
        vfprintf(log->fp, fmt, args);
        va_end(args);

        fprintf(log->fp, "\n");
    }

    fflush(log->fp);

    /* Release lock */
    uk_utils_thread_mutex_unlock(log->mutex);

    return true;
}

static void record_stacktrace(FILE *fp, uk_utils_stacktrace *stacktrace) {
    uk_utils_stacktrace_print_fd_this(stacktrace, fp);
}

bool uk_utils_logger_record_stacktrace(uk_utils_logger *log, uk_utils_stacktrace *stacktrace, const char *message, const char *file, int line) {
    unsigned short int padding_size;
    time_t rawtime;
    struct tm *timeinfo;
    char *date_time, *message_color;

    if (!log) {
        uk_utils_stacktrace_push_msg("Specified log ptr is null");
        return false;
    }

    /* Acquire lock */
    uk_utils_thread_mutex_lock(log->mutex);

    /* Get current time */
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    date_time = asctime(timeinfo);
    date_time[strlen(date_time) - 1] = '\0';

    if (log->padding) {
        padding_size = LEVEL_NAME_MAX_SIZE - strlen(log->level_names[UnknownKrakenUtils_LOG_WARNING]);
    } else {
        padding_size = 0;
    }

    /* Log to stdout */
    if (UnknownKrakenUtils_LOG_ERROR >= log->print_level) {
        if (log->message_color_as_level_color) {
            message_color = log->level_colors[UnknownKrakenUtils_LOG_ERROR];
        } else {
            message_color = log->message_color;
        }

        if (log->colored) {
            if (log->details) {
                fprintf(stdout, "%s[%s] [%s:%d] ", log->level_colors[UnknownKrakenUtils_LOG_ERROR], date_time, file, line);
            }

            fprintf(stdout, "%s[%s]%*s%s %s", log->level_colors[UnknownKrakenUtils_LOG_ERROR], log->level_names[UnknownKrakenUtils_LOG_ERROR], padding_size,
                "", UnknownKrakenUtils_WHITE_COLOR, message_color);
        } else {
            if (log->details) {
                fprintf(stdout, "[%s] [%s:%d] ", date_time, file, line);
            }

            fprintf(stdout, "[%s]%*s ", log->level_names[UnknownKrakenUtils_LOG_ERROR], padding_size, "");
        }

        fprintf(stdout, "%s", message);
        if (log->colored) {
            fprintf(stdout, "%s", UnknownKrakenUtils_WHITE_COLOR);
        }
        fprintf(stdout, "\n");
        record_stacktrace(stdout, stacktrace);
        fflush(stdout);
    }

    /* Log to file */
    if (log->fp != NULL && UnknownKrakenUtils_LOG_ERROR >= log->file_level) {
        if (log->details) {
            fprintf(log->fp, " [%s] [%s:%d] ", date_time, file, line);
        }

        fprintf(log->fp, "[%s]%*s %s\n", log->level_names[UnknownKrakenUtils_LOG_ERROR], padding_size, "", message);

        record_stacktrace(log->fp, stacktrace);
    }

    /* Release lock */
    uk_utils_thread_mutex_unlock(log->mutex);

    return true;
}

FILE *uk_utils_logger_get_fp(uk_utils_logger *log) {
    return log->fp;
}
