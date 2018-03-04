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
#include <unknownecho/system/alloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LEVEL_NAME_MAX_SIZE 5
static const char *level_names[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

static const char *level_colors[] = {
    "\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m"
};

ue_logger *ue_logger_create() {
    ue_logger *log;

    ue_safe_alloc(log, ue_logger, 1);
    log->print_level = 0;
    log->file_level = 0;
    log->quiet = false;
    log->fp = stdout;
    log->mutex = ue_thread_mutex_create();
    log->colored = true;
    log->details = true;

    return log;
}

void ue_logger_destroy(ue_logger *log) {
    if (log) {
        ue_thread_mutex_destroy(log->mutex);
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

void ue_logger_set_quiet(ue_logger *log, bool enable) {
    log->quiet = enable ? true : false;
}

void ue_logger_set_colored(ue_logger *log, bool enable) {
    log->colored = enable;
}

void ue_logger_set_details(ue_logger *log, bool enable) {
    log->details = enable;
}

bool ue_logger_record(ue_logger *log, int level, const char *file, int line, const char *fmt, ...) {
    time_t rawtime;
    struct tm *timeinfo;
    va_list args;
    char *date_time;
    unsigned short int padding;

    if (!log) {
        ue_stacktrace_push_msg("Specified log ptr is null");
        return false;
    }

    /* Acquire lock */
    ue_thread_mutex_lock(log->mutex);

    /* Get current time */
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    date_time = asctime(timeinfo);
    date_time[strlen(date_time) - 1] = '\0';

    //padding = LEVEL_NAME_MAX_SIZE - strlen(level_names[level]);
    padding = 0;

    /* Log to stdout */
    if (level >= log->print_level) {
        if (log->colored) {
            fprintf(stdout, "%s[%s%*s]\x1b[0m \x1b[90m", level_colors[level], level_names[level], padding, "");
        } else {
            fprintf(stdout, "[%s%*s] ", level_names[level], padding, "");
        }

        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
        if (log->colored) {
            fprintf(stdout, "\x1b[0m");
        }
        fprintf(stdout, "\n");
    }

    /* Log to file */
    if (log->fp != NULL && level >= log->file_level) {
        fprintf(log->fp, "[%s%*s] ", level_names[level], padding, "");

        va_start(args, fmt);
        vfprintf(log->fp, fmt, args);
        va_end(args);
        if (log->details) {
            fprintf(log->fp, " %s:%d at %s\n", file, line, date_time);
        } else {
            fprintf(log->fp, "\n");
        }
    }

    fflush(log->fp);

    /* Release lock */
    ue_thread_mutex_unlock(log->mutex);

    return true;
}

static void record_stacktrace(FILE *fp, ue_stacktrace *stacktrace) {
    ue_stacktrace_print_fd_this(stacktrace, fp);
}

bool ue_logger_record_stacktrace(ue_logger *log, ue_stacktrace *stacktrace, const char *message, const char *file, int line) {
    unsigned short int padding;
    time_t rawtime;
    struct tm *timeinfo;
    char *date_time;

    if (!log) {
        ue_stacktrace_push_msg("Specified log ptr is null");
        return false;
    }

    /* Acquire lock */
    ue_thread_mutex_lock(log->mutex);

    /* Get current time */
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    date_time = asctime(timeinfo);
    date_time[strlen(date_time) - 1] = '\0';

    //padding = LEVEL_NAME_MAX_SIZE - strlen(level_names[LOG_ERROR]);
    padding = 0;

    /* Log to stdout */
    if (LOG_ERROR >= log->print_level) {
        if (log->colored) {
            fprintf(stdout, "%s[%s%*s]\x1b[0m \x1b[90m", level_colors[LOG_ERROR], level_names[LOG_ERROR], padding, "");
        } else {
            fprintf(stdout, "[%s%*s] ", level_names[LOG_ERROR], padding, "");
        }

        fprintf(stdout, "%s", message);
        if (log->colored) {
            fprintf(stdout, "\x1b[0m");
        }
        fprintf(stdout, "\n");
        record_stacktrace(stdout, stacktrace);
    }

    /* Log to file */
    if (log->fp != NULL && LOG_ERROR >= log->file_level) {
        fprintf(log->fp, "[%s%*s] ", level_names[LOG_ERROR], padding, "");

        fprintf(log->fp, "%s", message);
        if (log->details) {
            fprintf(log->fp, " %s:%d at %s", file, line, date_time);
        }
        fprintf(log->fp, "\n");
        record_stacktrace(log->fp, stacktrace);
    }

    fflush(log->fp);

    /* Release lock */
    ue_thread_mutex_unlock(log->mutex);

    return true;
}

FILE *ue_logger_get_fp(ue_logger *log) {
    return log->fp;
}
