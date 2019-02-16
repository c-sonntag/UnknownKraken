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

#ifndef UNKNOWNECHOUTILSMODULE_QUEUE_H
#define UNKNOWNECHOUTILSMODULE_QUEUE_H

#include <ueum/compiler/bool.h>
#include <ueum/thread/thread_mutex.h>
#include <ueum/thread/thread_cond.h>

#include <stdio.h>

struct ueum_queue_node {
    void *data;
    struct ueum_queue_node *ptr;
};

typedef struct {
    struct ueum_queue_node *front, *rear, *temp, *front1;
    int count;
    void (*user_print_func)(void *data, FILE *fd);
    void *(*user_alloc_func)(void *data);
    void (*user_free_func)(void *data);
    ueum_thread_mutex *mutex;
    ueum_thread_cond *write_cond, *read_cond;
} ueum_queue;

ueum_queue *ueum_queue_create();

ueum_queue *ueum_queue_create_mem(void *(*alloc_func)(void *data), void (*free_func)(void *data));

void ueum_queue_destroy(ueum_queue *queue);

void ueum_queue_clean_up(ueum_queue *queue);

bool ueum_queue_push(ueum_queue *queue, void *data);

/**
 * Set capacity for regulate the size
 */
bool ueum_queue_push_wait(ueum_queue *queue, void *data);

bool ueum_queue_pop(ueum_queue *queue);

int ueum_queue_size(ueum_queue *queue);

void *ueum_queue_front(ueum_queue *queue);

void *ueum_queue_front_wait(ueum_queue *queue);

bool ueum_queue_empty(ueum_queue *queue);

bool ueum_queue_print(ueum_queue *queue, FILE *fd);

bool ueum_queue_set_print_func(ueum_queue *queue, void (*print_func)(void *data, FILE *fd));

#endif
