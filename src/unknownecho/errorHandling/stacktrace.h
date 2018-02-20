#ifndef UNKNOWNECHO_STRACKTRACE_H
#define UNKNOWNECHO_STRACKTRACE_H

#include <unknownecho/errorHandling/error.h>
#include <unknownecho/errorHandling/internal_error.h>
#include <unknownecho/errorHandling/stacktrace_struct.h>
#include <unknownecho/bool.h>
#include <unknownecho/thread/thread_storage.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

void ue_stacktrace_create(ue_stacktrace **stack);

void ue_stacktrace_destroy(ue_stacktrace *stack);

void push_to_stacktrace(ue_stacktrace *stack, ue_error *e);

char *ue_stacktrace_to_string(ue_stacktrace *stack);

void ue_stacktrace_print();

void ue_stacktrace_print_all();

void ue_stacktrace_print_fd_all(FILE *fd);

void ue_stacktrace_print_this(ue_stacktrace *stack);

void ue_stacktrace_print_fd(FILE *fd);

void ue_stacktrace_print_fd_this(ue_stacktrace *stack, FILE *fd);

char *ue_stacktrace_get_cause();

char *ue_stacktrace_get_cause_this(ue_stacktrace *stack);

bool ue_stacktrace_is_filled_this(ue_stacktrace *stack);

bool ue_stacktrace_is_filled();

void ue_stacktrace_clean_up();

#define ue_stacktrace_push_code(code) \
    char *description; \
    description = ue_internal_error_get_description(code); \
    push_to_stacktrace(ue_thread_storage_get_stacktrace(), ue_error_create((char *)__func__, __FILE__, __LINE__, description)); \
    free((void*)description); \

#define ue_stacktrace_push_errno() \
    char *description; \
    if (errno == 0) { \
        description = ue_internal_error_get_description(UNKNOWNECHO_UNKNOWN_ERROR); \
        push_to_stacktrace(ue_thread_storage_get_stacktrace(), ue_error_create((char *)__func__, __FILE__, __LINE__, description)); \
        free((void*)description); \
    } else { \
        push_to_stacktrace(ue_thread_storage_get_stacktrace(), ue_error_create((char *)__func__, __FILE__, __LINE__, strerror(errno))); \
    } \

#define ue_stacktrace_push_msg(...) \
    push_to_stacktrace(ue_thread_storage_get_stacktrace(), ue_error_create_variadic((char *)__func__, __FILE__, __LINE__, __VA_ARGS__)); \

#endif
