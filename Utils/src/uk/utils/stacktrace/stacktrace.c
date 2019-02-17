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

#include <uk/utils/stacktrace/stacktrace.h>

#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#else
    #include <pthread.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
    #define uk_utils_get_current_thread_id() GetCurrentThreadId()
#else
    #define uk_utils_get_current_thread_id() pthread_self()
#endif

#define MAX_STACK_SIZE 10

void uk_utils_stacktrace_create(uk_utils_stacktrace **stack) {
    (*stack) = (uk_utils_stacktrace *)malloc(sizeof(uk_utils_stacktrace));
    if (errno == ENOMEM || !(*stack)) {
        free((void *)(*stack));
        return;
    }
    memset((*stack), 0, sizeof(uk_utils_stacktrace));


    (*stack)->errors = (uk_utils_error **)malloc(MAX_STACK_SIZE * sizeof(uk_utils_error *));
    memset((*stack)->errors, 0, MAX_STACK_SIZE * sizeof(uk_utils_error *));
    (*stack)->elements = 0;
    (*stack)->uk_utils_thread_id = uk_utils_get_current_thread_id();
}

void uk_utils_stacktrace_destroy(uk_utils_stacktrace *stack) {
    unsigned short i;

    if (stack) {
        if (stack->errors) {
            for (i = 0; i < MAX_STACK_SIZE; i++) {
                uk_utils_error_destroy(stack->errors[i]);
            }
            free((void *)stack->errors);
        }
        free((void *)stack);
    }
}

void push_to_stacktrace(uk_utils_stacktrace *stack, uk_utils_error *e) {
    if (!stack || !e) {
        return;
    }

    if (stack->elements == MAX_STACK_SIZE) {
        return;
    }

    stack->errors[stack->elements] = e;

    stack->elements++;
}

char *uk_utils_stacktrace_to_string(uk_utils_stacktrace *stack) {
    int size;
    unsigned short i;
    char *uk_utils_stacktrace_buffer, *error_buffer, *uk_utils_thread_id_buffer;

    if (stack->elements == 0) {
        return NULL;
    }

    uk_utils_thread_id_buffer = (char *)malloc(20 * sizeof(char));
    sprintf(uk_utils_thread_id_buffer, "%lu", stack->uk_utils_thread_id);

    /**
     * Print the most important error at the top of the stacktrace,
     * unless there's only one error in the stacktrace.
     */
    stack->errors[0]->is_main_error = stack->elements > 1 ? true : false;

    size = 0;
    size = strlen(stack->errors[stack->elements - 1]->description);
    size += strlen(" (thread ");
    size += strlen(uk_utils_thread_id_buffer);
    size += strlen(")\n");
    for (i = 0; i < stack->elements; i++) {
        error_buffer = uk_utils_internal_error_to_string(stack->errors[i]);
        size += strlen(error_buffer);
        size += strlen("\n");
        free((void *)error_buffer);
    }

    uk_utils_stacktrace_buffer = (char *)malloc((size + 1) * sizeof(char));
    if (errno == ENOMEM || !uk_utils_stacktrace_buffer) {
        free((void *)uk_utils_stacktrace_buffer);
        return NULL;
    }
    sprintf(uk_utils_stacktrace_buffer, "%s (thread %s)\n",
        stack->errors[stack->elements - 1]->description, uk_utils_thread_id_buffer);
    for (i = 0; i < stack->elements; i++) {
        error_buffer = uk_utils_internal_error_to_string(stack->errors[i]);
        strcat(uk_utils_stacktrace_buffer, error_buffer);
        strcat(uk_utils_stacktrace_buffer, "\n");
        free((void *)error_buffer);
    }

    free((void *)uk_utils_thread_id_buffer);

    return uk_utils_stacktrace_buffer;
}

void uk_utils_stacktrace_print_this(uk_utils_stacktrace *stack) {
    if (!stack) {
        return;
    }

    uk_utils_stacktrace_print_fd_this(stack, stderr);
}

void uk_utils_stacktrace_print() {
    uk_utils_stacktrace_print_this(uk_utils_thread_storage_get_stacktrace());
}

void uk_utils_stacktrace_print_all() {
    uk_utils_stacktrace_print_fd_all(stderr);
}

void uk_utils_stacktrace_print_fd_all(FILE *fd) {
    uk_utils_stacktrace **stacks;
    int i, number;

    stacks = uk_utils_thread_storage_get_all_stacktrace(&number);

    for (i = 0; i < number; i++) {
        if (stacks[i] && uk_utils_stacktrace_is_filled_this(stacks[i])) {
            uk_utils_stacktrace_print_fd_this(stacks[i], fd);
            fprintf(fd, "\n");
        }
    }

    free((void *)stacks);
}

void uk_utils_stacktrace_print_fd_this(uk_utils_stacktrace *stack, FILE *fd) {
    char *uk_utils_stacktrace_buffer;

    if (!stack) {
        return;
    }

    uk_utils_stacktrace_buffer = uk_utils_stacktrace_to_string(stack);

    if (uk_utils_stacktrace_buffer) {
        fprintf(fd, "%s", uk_utils_stacktrace_buffer);
        free((void *)uk_utils_stacktrace_buffer);
    }
}

void uk_utils_stacktrace_print_fd(FILE *fd) {
    uk_utils_stacktrace_print_fd_this(uk_utils_thread_storage_get_stacktrace(), fd);
}

char *uk_utils_stacktrace_get_cause_this(uk_utils_stacktrace *stack) {
    if (stack->elements == 0) {
        return NULL;
    }

    return stack->errors[0]->description;
}

char *uk_utils_stacktrace_get_cause() {
    return uk_utils_stacktrace_get_cause_this(uk_utils_thread_storage_get_stacktrace());
}

bool uk_utils_stacktrace_is_filled_this(uk_utils_stacktrace *stack) {
    return stack && stack->elements > 0 ? true : false;
}

bool uk_utils_stacktrace_is_filled() {
    return uk_utils_stacktrace_is_filled_this(uk_utils_thread_storage_get_stacktrace());
}

void uk_utils_stacktrace_clean_up() {
    uk_utils_stacktrace *stack;
    unsigned short i;

    stack = uk_utils_thread_storage_get_stacktrace();

    if (stack) {
        if (stack->errors) {
            for (i = 0; i < MAX_STACK_SIZE; i++) {
                uk_utils_error_clean_up(stack->errors[i]);
            }
        }
        stack->elements = 0;
    }
}
