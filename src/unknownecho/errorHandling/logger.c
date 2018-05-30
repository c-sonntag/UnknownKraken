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

/*
 * Inspired by log.c of rxi on Github : https://github.com/rxi/log.c
 *
 * Copyright (c) 2017 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See `log.c` for details.
 */

#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/alloc.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/defines.h>

#include <uv.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LEVEL_NAME_MAX_SIZE  7

static const char *level_names[] = {
    "TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "FATAL"
};

ue_logger *ue_logger_create() {
    ue_logger *log;

    ue_safe_alloc(log, ue_logger, 1);
    log->print_level = 0;
    log->file_level = 0;
    log->fp = NULL;
    uv_mutex_init(&log->mutex);
    log->colored = true;
    log->details = true;
    log->padding = false;
    log->message_color_as_level_color = false;

    ue_safe_alloc(log->level_colors, char *, 6);
    log->level_colors[UNKNOWNECHO_LOG_TRACE] = ue_string_create_from(UNKNOWNECHO_SKY_BLUE_COLOR);
    log->level_colors[UNKNOWNECHO_LOG_DEBUG] = ue_string_create_from(UNKNOWNECHO_TURQUOISE_BLUE_COLOR);
    log->level_colors[UNKNOWNECHO_LOG_INFO] = ue_string_create_from(UNKNOWNECHO_GREEN_COLOR);
    log->level_colors[UNKNOWNECHO_LOG_WARNING] = ue_string_create_from(UNKNOWNECHO_YELLOW_COLOR);
    log->level_colors[UNKNOWNECHO_LOG_ERROR] = ue_string_create_from(UNKNOWNECHO_RED_COLOR);
    log->level_colors[UNKNOWNECHO_LOG_FATAL] = ue_string_create_from(UNKNOWNECHO_PURPLE_COLOR);

    log->message_color = ue_string_create_from(UNKNOWNECHO_WHITE_COLOR);

    return log;
}

void ue_logger_destroy(ue_logger *log) {
    if (log) {
        uv_mutex_destroy(&log->mutex);
        ue_safe_free(log->level_colors[UNKNOWNECHO_LOG_TRACE]);
        ue_safe_free(log->level_colors[UNKNOWNECHO_LOG_DEBUG]);
        ue_safe_free(log->level_colors[UNKNOWNECHO_LOG_INFO]);
        ue_safe_free(log->level_colors[UNKNOWNECHO_LOG_WARNING]);
        ue_safe_free(log->level_colors[UNKNOWNECHO_LOG_ERROR]);
        ue_safe_free(log->level_colors[UNKNOWNECHO_LOG_FATAL]);
        ue_safe_free(log->level_colors);
        ue_safe_free(log->message_color);
        ue_safe_free(log);
    }
}

void ue_logger_set_fp(ue_logger *log, FILE *fp) {
    log->fp = fp;
}

void ue_logger_set_file_level(ue_logger *log, int level) {
    log->file_level = level;
}

void ue_logger_set_print_level(ue_logger *log, int level) {
    log->print_level = level;
}

int ue_logger_get_print_level(ue_logger *log) {
    return  log->print_level;
}

int ue_logger_get_file_level(ue_logger *log) {
    return  log->file_level;
}

void ue_logger_set_colored(ue_logger *log, bool enable) {
    log->colored = enable;
}

void ue_logger_set_details(ue_logger *log, bool enable) {
    log->details = enable;
}

void ue_logger_set_padding(ue_logger *log, bool enable) {
    log->padding = enable;
}

void ue_logger_set_message_color(ue_logger *log, const char *color) {
    ue_safe_free(log->message_color);
    log->message_color = ue_string_create_from(color);
}

void ue_logger_set_message_color_as_level_color(ue_logger *log, bool enable) {
    log->message_color_as_level_color = enable;
}

bool ue_logger_record(ue_logger *log, int level, const char *file, int line, const char *fmt, ...) {
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
    uv_mutex_lock(&log->mutex);

    /* Get current time */
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    date_time = asctime(timeinfo);
    date_time[strlen(date_time) - 1] = '\0';

    if (log->padding) {
        padding_size = LEVEL_NAME_MAX_SIZE - strlen(level_names[level]);
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

            fprintf(stdout, "%s[%s]%*s%s %s", log->level_colors[level], level_names[level], padding_size,
                "", UNKNOWNECHO_WHITE_COLOR, message_color);
        } else {
            if (log->details) {
                fprintf(stdout, "[%s] [%s:%d] ", date_time, file, line);
            }

            fprintf(stdout, "[%s]%*s ", level_names[level], padding_size, "");
        }

        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
        if (log->colored) {
            fprintf(stdout, "%s", UNKNOWNECHO_WHITE_COLOR);
        }
        fprintf(stdout, "\n");
    }

    /* Log to file */
    if (log->fp != NULL && level >= log->file_level) {
        if (log->details) {
            fprintf(log->fp, "[%s] [%s:%d] ", date_time, file, line);
        }

        fprintf(log->fp, "[%s]%*s ", level_names[level], padding_size, "");

        va_start(args, fmt);
        vfprintf(log->fp, fmt, args);
        va_end(args);

        fprintf(log->fp, "\n");
    }

    fflush(log->fp);

    /* Release lock */
    uv_mutex_unlock(&log->mutex);

    return true;
}

static void record_stacktrace(FILE *fp, ue_stacktrace *stacktrace) {
    ue_stacktrace_print_fd_this(stacktrace, fp);
}

bool ue_logger_record_stacktrace(ue_logger *log, ue_stacktrace *stacktrace, const char *message, const char *file, int line) {
    unsigned short int padding_size;
    time_t rawtime;
    struct tm *timeinfo;
    char *date_time, *message_color;

    if (!log) {
        ue_stacktrace_push_msg("Specified log ptr is null");
        return false;
    }

    /* Acquire lock */
    uv_mutex_lock(&log->mutex);

    /* Get current time */
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    date_time = asctime(timeinfo);
    date_time[strlen(date_time) - 1] = '\0';

    if (log->padding) {
        padding_size = LEVEL_NAME_MAX_SIZE - strlen(level_names[UNKNOWNECHO_LOG_WARNING]);
    } else {
        padding_size = 0;
    }

    /* Log to stdout */
    if (UNKNOWNECHO_LOG_ERROR >= log->print_level) {
        if (log->message_color_as_level_color) {
            message_color = log->level_colors[UNKNOWNECHO_LOG_ERROR];
        } else {
            message_color = log->message_color;
        }

        if (log->colored) {
            if (log->details) {
                fprintf(stdout, "%s[%s] [%s:%d] ", log->level_colors[UNKNOWNECHO_LOG_ERROR], date_time, file, line);
            }

            fprintf(stdout, "%s[%s]%*s%s %s", log->level_colors[UNKNOWNECHO_LOG_ERROR], level_names[UNKNOWNECHO_LOG_ERROR], padding_size,
                "", UNKNOWNECHO_WHITE_COLOR, message_color);
        } else {
            if (log->details) {
                fprintf(stdout, "[%s] [%s:%d] ", date_time, file, line);
            }

            fprintf(stdout, "[%s]%*s ", level_names[UNKNOWNECHO_LOG_ERROR], padding_size, "");
        }

        fprintf(stdout, "%s", message);
        if (log->colored) {
            fprintf(stdout, "%s", UNKNOWNECHO_WHITE_COLOR);
        }
        fprintf(stdout, "\n");
        record_stacktrace(stdout, stacktrace);
        fflush(stdout);
    }

    /* Log to file */
    if (log->fp != NULL && UNKNOWNECHO_LOG_ERROR >= log->file_level) {
        if (log->details) {
            fprintf(log->fp, " [%s] [%s:%d] ", date_time, file, line);
        }

        fprintf(log->fp, "[%s]%*s %s\n", level_names[UNKNOWNECHO_LOG_ERROR], padding_size, "", message);

        record_stacktrace(log->fp, stacktrace);
    }

    /* Release lock */
    uv_mutex_unlock(&log->mutex);

    return true;
}

FILE *ue_logger_get_fp(ue_logger *log) {
    return log->fp;
}
