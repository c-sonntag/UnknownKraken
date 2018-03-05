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

#include <unknownecho/errorHandling/stacktrace.h>

#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#else
    #include <pthread.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
    #define ue_get_current_thread_id() GetCurrentThreadId()
#else
    #define ue_get_current_thread_id() pthread_self()
#endif

#define MAX_STACK_SIZE 10

void ue_stacktrace_create(ue_stacktrace **stack) {
    (*stack) = (ue_stacktrace *)malloc(sizeof(ue_stacktrace));
    if (errno == ENOMEM || !(*stack)) {
		free((void *)(*stack));
		return;
	}
    memset((*stack), 0, sizeof(ue_stacktrace));


    (*stack)->errors = (ue_error **)malloc(MAX_STACK_SIZE * sizeof(ue_error *));
	memset((*stack)->errors, 0, MAX_STACK_SIZE * sizeof(ue_error *));
	(*stack)->elements = 0;
	(*stack)->ue_thread_id = ue_get_current_thread_id();
}

void ue_stacktrace_destroy(ue_stacktrace *stack) {
    unsigned short i;

	if (stack) {
		if (stack->errors) {
			for (i = 0; i < MAX_STACK_SIZE; i++) {
				ue_error_destroy(stack->errors[i]);
			}
			free((void *)stack->errors);
		}
		free((void *)stack);
	}
}

void push_to_stacktrace(ue_stacktrace *stack, ue_error *e) {
    if (!stack || !e) {
        return;
    }

	if (stack->elements == MAX_STACK_SIZE) {
		return;
	}

	stack->errors[stack->elements] = e;

	stack->elements++;
}

char *ue_stacktrace_to_string(ue_stacktrace *stack) {
	int size;
    unsigned short i;
	char *ue_stacktrace_buffer, *error_buffer, *ue_thread_id_buffer;

	if (stack->elements == 0) {
		return NULL;
	}

	ue_thread_id_buffer = (char *)malloc(20 * sizeof(char));
	sprintf(ue_thread_id_buffer, "%lu", stack->ue_thread_id);

	/* Print the most important error at the top of the stacktrace */
	stack->errors[0]->is_main_error = true;

	size = 0;
	size = strlen(stack->errors[stack->elements - 1]->description);
	size += strlen(" (thread ");
	size += strlen(ue_thread_id_buffer);
	size += strlen(")\n");
	for (i = 0; i < stack->elements; i++) {
		error_buffer = ue_internal_error_to_string(stack->errors[i]);
		size += strlen(error_buffer);
		size += strlen("\n");
		free((void *)error_buffer);
	}

	ue_stacktrace_buffer = (char*)malloc((size + 1) * sizeof(char));
	if (errno == ENOMEM || !ue_stacktrace_buffer) {
		free((void *)ue_stacktrace_buffer);
		return NULL;
	}
	sprintf(ue_stacktrace_buffer, "%s (thread %s)\n",
		stack->errors[stack->elements - 1]->description, ue_thread_id_buffer);
	for (i = 0; i < stack->elements; i++) {
		error_buffer = ue_internal_error_to_string(stack->errors[i]);
		strcat(ue_stacktrace_buffer, error_buffer);
		strcat(ue_stacktrace_buffer, "\n");
		free((void *)error_buffer);
	}

	free((void *)ue_thread_id_buffer);

	return ue_stacktrace_buffer;
}

void ue_stacktrace_print_this(ue_stacktrace *stack) {
	if (!stack) {
		return;
	}

    ue_stacktrace_print_fd_this(stack, stderr);
}

void ue_stacktrace_print() {
    ue_stacktrace_print_this(ue_thread_storage_get_stacktrace());
}

void ue_stacktrace_print_all() {
	ue_stacktrace_print_fd_all(stderr);
}

void ue_stacktrace_print_fd_all(FILE *fd) {
	ue_stacktrace **stacks;
	int i, number;

	stacks = ue_thread_storage_get_all_stacktrace(&number);

	for (i = 0; i < number; i++) {
		if (stacks[i] && ue_stacktrace_is_filled_this(stacks[i])) {
			ue_stacktrace_print_fd_this(stacks[i], fd);
			fprintf(fd, "\n");
		}
	}

	free((void *)stacks);
}

void ue_stacktrace_print_fd_this(ue_stacktrace *stack, FILE *fd) {
    char *ue_stacktrace_buffer;

	if (!stack) {
		return;
	}

	ue_stacktrace_buffer = ue_stacktrace_to_string(stack);

	if (ue_stacktrace_buffer) {
		fprintf(fd, "%s", ue_stacktrace_buffer);
		free((void *)ue_stacktrace_buffer);
	}
}

void ue_stacktrace_print_fd(FILE *fd) {
    ue_stacktrace_print_fd_this(ue_thread_storage_get_stacktrace(), fd);
}

char *ue_stacktrace_get_cause_this(ue_stacktrace *stack) {
	if (stack->elements == 0) {
		return NULL;
	}

	return stack->errors[0]->description;
}

char *ue_stacktrace_get_cause() {
    return ue_stacktrace_get_cause_this(ue_thread_storage_get_stacktrace());
}

bool ue_stacktrace_is_filled_this(ue_stacktrace *stack) {
	return stack->elements > 0 ? true : false;
}

bool ue_stacktrace_is_filled() {
	return ue_stacktrace_is_filled_this(ue_thread_storage_get_stacktrace());
}

void ue_stacktrace_clean_up() {
    ue_stacktrace *stack;
    unsigned short i;

    stack = ue_thread_storage_get_stacktrace();

    if (stack) {
		if (stack->errors) {
			for (i = 0; i < MAX_STACK_SIZE; i++) {
				ue_error_clean_up(stack->errors[i]);
			}
		}
        stack->elements = 0;
    }
}
