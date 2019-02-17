/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoUtilsModule.                             *
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

#ifndef UnknownKrakenUtils_QUEUE_H
#define UnknownKrakenUtils_QUEUE_H

#include <uk/utils/compiler/bool.h>
#include <uk/utils/thread/thread_mutex.h>
#include <uk/utils/thread/thread_cond.h>

#include <stdio.h>

struct uk_utils_queuk_ue_node {
    void *data;
    struct uk_utils_queuk_ue_node *ptr;
};

typedef struct {
    struct uk_utils_queuk_ue_node *front, *rear, *temp, *front1;
    int count;
    void (*user_print_func)(void *data, FILE *fd);
    void *(*user_alloc_func)(void *data);
    void (*user_free_func)(void *data);
    uk_utils_thread_mutex *mutex;
    uk_utils_thread_cond *write_cond, *read_cond;
} uk_utils_queue;

uk_utils_queue *uk_utils_queuk_ue_create();

uk_utils_queue *uk_utils_queuk_ue_create_mem(void *(*alloc_func)(void *data), void (*free_func)(void *data));

void uk_utils_queuk_ue_destroy(uk_utils_queue *queue);

void uk_utils_queuk_ue_clean_up(uk_utils_queue *queue);

bool uk_utils_queuk_ue_push(uk_utils_queue *queue, void *data);

/**
 * Set capacity for regulate the size
 */
bool uk_utils_queuk_ue_push_wait(uk_utils_queue *queue, void *data);

bool uk_utils_queuk_ue_pop(uk_utils_queue *queue);

int uk_utils_queuk_ue_size(uk_utils_queue *queue);

void *uk_utils_queuk_ue_front(uk_utils_queue *queue);

void *uk_utils_queuk_ue_front_wait(uk_utils_queue *queue);

bool uk_utils_queuk_ue_empty(uk_utils_queue *queue);

bool uk_utils_queuk_ue_print(uk_utils_queue *queue, FILE *fd);

bool uk_utils_queuk_ue_set_print_func(uk_utils_queue *queue, void (*print_func)(void *data, FILE *fd));

#endif
