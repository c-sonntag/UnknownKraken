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

#include <ei/stacktrace/stacktrace.h>

#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#else
    #include <pthread.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
    #define ei_get_current_thread_id() GetCurrentThreadId()
#else
    #define ei_get_current_thread_id() pthread_self()
#endif

#define MAX_STACK_SIZE 10

void ei_stacktrace_create(ei_stacktrace **stack) {
    (*stack) = (ei_stacktrace *)malloc(sizeof(ei_stacktrace));
    if (errno == ENOMEM || !(*stack)) {
        free((void *)(*stack));
        return;
    }
    memset((*stack), 0, sizeof(ei_stacktrace));


    (*stack)->errors = (ei_error **)malloc(MAX_STACK_SIZE * sizeof(ei_error *));
    memset((*stack)->errors, 0, MAX_STACK_SIZE * sizeof(ei_error *));
    (*stack)->elements = 0;
    (*stack)->ei_thread_id = ei_get_current_thread_id();
}

void ei_stacktrace_destroy(ei_stacktrace *stack) {
    unsigned short i;

    if (stack) {
        if (stack->errors) {
            for (i = 0; i < MAX_STACK_SIZE; i++) {
                ei_error_destroy(stack->errors[i]);
            }
            free((void *)stack->errors);
        }
        free((void *)stack);
    }
}

void push_to_stacktrace(ei_stacktrace *stack, ei_error *e) {
    if (!stack || !e) {
        return;
    }

    if (stack->elements == MAX_STACK_SIZE) {
        return;
    }

    stack->errors[stack->elements] = e;

    stack->elements++;
}

char *ei_stacktrace_to_string(ei_stacktrace *stack) {
    int size;
    unsigned short i;
    char *ei_stacktrace_buffer, *error_buffer, *ei_thread_id_buffer;

    if (stack->elements == 0) {
        return NULL;
    }

    ei_thread_id_buffer = (char *)malloc(20 * sizeof(char));
    sprintf(ei_thread_id_buffer, "%lu", stack->ei_thread_id);

    /**
     * Print the most important error at the top of the stacktrace,
     * unless there's only one error in the stacktrace.
     */
    stack->errors[0]->is_main_error = stack->elements > 1 ? true : false;

    size = 0;
    size = strlen(stack->errors[stack->elements - 1]->description);
    size += strlen(" (thread ");
    size += strlen(ei_thread_id_buffer);
    size += strlen(")\n");
    for (i = 0; i < stack->elements; i++) {
        error_buffer = ei_internal_error_to_string(stack->errors[i]);
        size += strlen(error_buffer);
        size += strlen("\n");
        free((void *)error_buffer);
    }

    ei_stacktrace_buffer = (char *)malloc((size + 1) * sizeof(char));
    if (errno == ENOMEM || !ei_stacktrace_buffer) {
        free((void *)ei_stacktrace_buffer);
        return NULL;
    }
    sprintf(ei_stacktrace_buffer, "%s (thread %s)\n",
        stack->errors[stack->elements - 1]->description, ei_thread_id_buffer);
    for (i = 0; i < stack->elements; i++) {
        error_buffer = ei_internal_error_to_string(stack->errors[i]);
        strcat(ei_stacktrace_buffer, error_buffer);
        strcat(ei_stacktrace_buffer, "\n");
        free((void *)error_buffer);
    }

    free((void *)ei_thread_id_buffer);

    return ei_stacktrace_buffer;
}

void ei_stacktrace_print_this(ei_stacktrace *stack) {
    if (!stack) {
        return;
    }

    ei_stacktrace_print_fd_this(stack, stderr);
}

void ei_stacktrace_print() {
    ei_stacktrace_print_this(ei_thread_storage_get_stacktrace());
}

void ei_stacktrace_print_all() {
    ei_stacktrace_print_fd_all(stderr);
}

void ei_stacktrace_print_fd_all(FILE *fd) {
    ei_stacktrace **stacks;
    int i, number;

    stacks = ei_thread_storage_get_all_stacktrace(&number);

    for (i = 0; i < number; i++) {
        if (stacks[i] && ei_stacktrace_is_filled_this(stacks[i])) {
            ei_stacktrace_print_fd_this(stacks[i], fd);
            fprintf(fd, "\n");
        }
    }

    free((void *)stacks);
}

void ei_stacktrace_print_fd_this(ei_stacktrace *stack, FILE *fd) {
    char *ei_stacktrace_buffer;

    if (!stack) {
        return;
    }

    ei_stacktrace_buffer = ei_stacktrace_to_string(stack);

    if (ei_stacktrace_buffer) {
        fprintf(fd, "%s", ei_stacktrace_buffer);
        free((void *)ei_stacktrace_buffer);
    }
}

void ei_stacktrace_print_fd(FILE *fd) {
    ei_stacktrace_print_fd_this(ei_thread_storage_get_stacktrace(), fd);
}

char *ei_stacktrace_get_cause_this(ei_stacktrace *stack) {
    if (stack->elements == 0) {
        return NULL;
    }

    return stack->errors[0]->description;
}

char *ei_stacktrace_get_cause() {
    return ei_stacktrace_get_cause_this(ei_thread_storage_get_stacktrace());
}

bool ei_stacktrace_is_filled_this(ei_stacktrace *stack) {
    return stack && stack->elements > 0 ? true : false;
}

bool ei_stacktrace_is_filled() {
    return ei_stacktrace_is_filled_this(ei_thread_storage_get_stacktrace());
}

void ei_stacktrace_clean_up() {
    ei_stacktrace *stack;
    unsigned short i;

    stack = ei_thread_storage_get_stacktrace();

    if (stack) {
        if (stack->errors) {
            for (i = 0; i < MAX_STACK_SIZE; i++) {
                ei_error_clean_up(stack->errors[i]);
            }
        }
        stack->elements = 0;
    }
}
