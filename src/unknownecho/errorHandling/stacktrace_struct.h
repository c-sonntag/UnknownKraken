#ifndef UNKNOWNECHO_STACKTRACE_STRUCT_H
#define UNKNOWNECHO_STACKTRACE_STRUCT_H

#include <unknownecho/errorHandling/error.h>

typedef struct {
    ue_error **errors;
    unsigned short elements;
    long ue_thread_id;
} ue_stacktrace;

#endif
