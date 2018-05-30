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

#include <unknownecho/container/queue.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

#include <stdio.h>


static bool ue_queue_push_internal(ue_queue *queue, void *data, bool wait);

static void *ue_queue_front_internal(ue_queue *queue, bool wait);


ue_queue *ue_queue_create() {
    ue_queue *queue;

    ue_safe_alloc(queue, ue_queue, 1);
    queue->front = queue->rear = NULL;
    queue->count = 0;
    queue->user_print_func = NULL;
    uv_mutex_init(&queue->mutex);
    uv_cond_init(&queue->read_cond);
    uv_cond_init(&queue->write_cond);
    queue->user_alloc_func = NULL;
    queue->user_free_func = NULL;

    return queue;
}

ue_queue *ue_queue_create_mem(void *(*alloc_func)(void *data), void (*free_func)(void *data)) {
    ue_queue *queue;

    ue_check_parameter_or_return(alloc_func);
    ue_check_parameter_or_return(free_func);

    queue = ue_queue_create();
    queue->user_alloc_func = alloc_func;
    queue->user_free_func = free_func;

    return queue;
}

void ue_queue_destroy(ue_queue *queue) {
    int i;

    if (queue) {
        for (i = 0; i < queue->count; i++) {
            ue_queue_pop(queue);
        }

        uv_mutex_destroy(&queue->mutex);
        uv_cond_destroy(&queue->read_cond);
        uv_cond_destroy(&queue->write_cond);

        ue_safe_free(queue);
    }
}

void ue_queue_clean_up(ue_queue *queue) {
    int i;

    if (queue) {
        for (i = 0; i < queue->count; i++) {
            ue_queue_pop(queue);
        }
    }
}

bool ue_queue_push(ue_queue *queue, void *data) {
    bool result;

    ue_check_parameter_or_return(queue);
    ue_check_parameter_or_return(data);

    uv_mutex_lock(&queue->mutex);

    result = ue_queue_push_internal(queue, data, false);

    uv_mutex_unlock(&queue->mutex);

    return result;
}

bool ue_queue_push_wait(ue_queue *queue, void *data) {
    bool result;

    ue_check_parameter_or_return(queue);
    ue_check_parameter_or_return(data);

    uv_mutex_lock(&queue->mutex);

    result = ue_queue_push_internal(queue, data, true);

    uv_mutex_unlock(&queue->mutex);

    return result;
}

bool ue_queue_pop(ue_queue *queue) {
    ue_check_parameter_or_return(queue);

    uv_mutex_lock(&queue->mutex);

    queue->front1 = queue->front;

    if (queue->front1 == NULL) {
        return true;
    }
    else {
        if (queue->front1->ptr != NULL) {
            queue->front1 = queue->front1->ptr;
            if (queue->user_free_func) {
                queue->user_free_func(queue->front->data);
            } else {
                queue->front->data = NULL;
            }
            ue_safe_free(queue->front);
            queue->front = queue->front1;
        }
        else {
            if (queue->user_free_func) {
                queue->user_free_func(queue->front->data);
            } else {
                queue->front->data = NULL;
            }
            ue_safe_free(queue->front);
            queue->front = NULL;
            queue->rear = NULL;
        }
        queue->count--;
    }

    uv_mutex_unlock(&queue->mutex);

    uv_cond_signal(&queue->write_cond);

    return true;
}

int ue_queue_size(ue_queue *queue) {
    int size;

    if (!queue) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return -1;
    }

    uv_mutex_lock(&queue->mutex);

    size = queue->count;

    uv_mutex_unlock(&queue->mutex);

    return size;
}

void *ue_queue_front(ue_queue *queue) {
    void *result;

    ue_check_parameter_or_return(queue);

    uv_mutex_lock(&queue->mutex);

    result = ue_queue_front_internal(queue, false);

    uv_mutex_unlock(&queue->mutex);

    return result;
}

void *ue_queue_front_wait(ue_queue *queue) {
    void *result;

    ue_check_parameter_or_return(queue);

    uv_mutex_lock(&queue->mutex);

    result = ue_queue_front_internal(queue, true);

    uv_mutex_unlock(&queue->mutex);

    return result;
}

bool ue_queue_empty(ue_queue *queue) {
    bool result;

    ue_check_parameter_or_return(queue);

    uv_mutex_lock(&queue->mutex);

    result = (queue->front == NULL) && (queue->rear == NULL);

    uv_mutex_unlock(&queue->mutex);

    return result;
}

bool ue_queue_print(ue_queue *queue, FILE *fd) {
    bool result;

    ue_check_parameter_or_return(queue);
    ue_check_parameter_or_return(fd);

    uv_mutex_lock(&queue->mutex);

    result = false;
    queue->front1 = queue->front;

    if ((queue->front1 == NULL) && (queue->rear == NULL)) {
        goto end;
    }

    if (queue->user_print_func == NULL) {
        ue_logger_warn("No print func specified by user");
        goto end;
    }

    while (queue->front1 != queue->rear) {
        queue->user_print_func(queue->front1->data, fd);
        queue->front1 = queue->front1->ptr;
    }

    if (queue->front1 == queue->rear) {
        queue->user_print_func(queue->front1->data, fd);
    }

    result = true;

end:
    uv_mutex_unlock(&queue->mutex);
    return result;
}

bool ue_queue_set_print_func(ue_queue *queue, void (*print_func)(void *data, FILE *fd)) {
    ue_check_parameter_or_return(queue);
    ue_check_parameter_or_return(print_func);

    queue->user_print_func = print_func;

    return true;
}

static bool ue_queue_push_internal(ue_queue *queue, void *data, bool wait) {
    /*if (queue->count == queue->capacity && wait) {
        while (queue->count == queue->capacity) {
            ue_thread_cond_wait(queue->write_cond, queue->mutex);
        }
    } else if (queue->count == queue->capacity) {
        ue_stacktrace_push_msg("Max capacity is reached");
        return false;
    }*/

    if (queue->rear == NULL) {
        ue_safe_alloc(queue->rear, struct ue_queue_node, 1);
        queue->rear->ptr = NULL;
        if (queue->user_alloc_func) {
            queue->rear->data = queue->user_alloc_func(data);
        } else {
            queue->rear->data = data;
        }
        queue->front = queue->rear;
    }
    else {
        ue_safe_alloc(queue->temp, struct ue_queue_node, 1);
        queue->rear->ptr = queue->temp;
        if (queue->user_alloc_func) {
            queue->temp->data = queue->user_alloc_func(data);
        } else {
            queue->temp->data = data;
        }
        queue->temp->ptr = NULL;

        queue->rear = queue->temp;
    }

    queue->count++;

    uv_cond_signal(&queue->read_cond);

    return true;
}

static void *ue_queue_front_internal(ue_queue *queue, bool wait) {
    void *result;

    result = NULL;

    if (wait && queue->count == 0) {
        uv_cond_wait(&queue->read_cond, &queue->mutex);
    } else if (queue->count == 0) {
        ue_stacktrace_push_msg("Queue is empty");
        return NULL;
    }

    if ((queue->front != NULL) && (queue->rear != NULL)) {
        result = queue->front->data;
    }

    return result;
}
