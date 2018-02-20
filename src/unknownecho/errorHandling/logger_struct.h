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
    int level;
    bool quiet;
    bool colored;
    bool details;
    FILE *fp;
    ue_thread_mutex *mutex;
} ue_logger;

#endif
