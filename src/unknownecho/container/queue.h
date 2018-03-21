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

 /**
  * Inspired from : http://www.sanfoundry.com/c-program-queue-using-linked-list for structure
  *
  * Inspired from : https://github.com/tobithiel/Queue for thread-safety logic
  * Associated copyright :
  *
  * Copyright (C) 2011 by Tobias Thiel
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in
  * all copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  * THE SOFTWARE.
  */

#ifndef UNKNOWNECHO_QUEUE_H
#define UNKNOWNECHO_QUEUE_H

#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/bool.h>

#include <stdio.h>

struct ue_queue_node {
    void *data;
    struct ue_queue_node *ptr;
};

typedef struct {
    struct ue_queue_node *front, *rear, *temp, *front1;
    int count;
    void (*user_print_func)(void *data, FILE *fd);
    void *(*user_alloc_func)(void *data);
    void (*user_free_func)(void *data);
    ue_thread_mutex *mutex;
    ue_thread_cond *write_cond, *read_cond;
} ue_queue;

ue_queue *ue_queue_create();

ue_queue *ue_queue_create_mem(void *(*alloc_func)(void *data), void (*free_func)(void *data));

void ue_queue_destroy(ue_queue *queue);

void ue_queue_clean_up(ue_queue *queue);

bool ue_queue_push(ue_queue *queue, void *data);

/**
 * Set capacity for regulate the size
 */
bool ue_queue_push_wait(ue_queue *queue, void *data);

bool ue_queue_pop(ue_queue *queue);

int ue_queue_size(ue_queue *queue);

void *ue_queue_front(ue_queue *queue);

void *ue_queue_front_wait(ue_queue *queue);

bool ue_queue_empty(ue_queue *queue);

bool ue_queue_print(ue_queue *queue, FILE *fd);

bool ue_queue_set_print_func(ue_queue *queue, void (*print_func)(void *data, FILE *fd));

#endif
