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

#include <ueum/container/queue.h>
#include <ueum/safe/safe_alloc.h>
#include <ei/ei.h>

#include <stdio.h>


static bool ueum_queue_push_internal(ueum_queue *queue, void *data, bool wait);

static void *ueum_queue_front_internal(ueum_queue *queue, bool wait);


ueum_queue *ueum_queue_create() {
    ueum_queue *queue;

    queue = NULL;

    ueum_safe_alloc(queue, ueum_queue, 1);
    queue->front = queue->rear = NULL;
    queue->count = 0;
    queue->user_print_func = NULL;
    queue->mutex = ueum_thread_mutex_create();
    queue->read_cond = ueum_thread_cond_create();
    queue->write_cond = ueum_thread_cond_create();
    queue->user_alloc_func = NULL;
    queue->user_free_func = NULL;

    return queue;
}

ueum_queue *ueum_queue_create_mem(void *(*alloc_func)(void *data), void (*free_func)(void *data)) {
    ueum_queue *queue;

    ei_check_parameter_or_return(alloc_func);
    ei_check_parameter_or_return(free_func);

    queue = ueum_queue_create();
    queue->user_alloc_func = alloc_func;
    queue->user_free_func = free_func;

    return queue;
}

void ueum_queue_destroy(ueum_queue *queue) {
    int i;

    if (queue) {
        for (i = 0; i < queue->count; i++) {
            ueum_queue_pop(queue);
        }

        ueum_thread_mutex_destroy(queue->mutex);
        ueum_thread_cond_destroy(queue->read_cond);
        ueum_thread_cond_destroy(queue->write_cond);

        ueum_safe_free(queue);
    }
}

void ueum_queue_clean_up(ueum_queue *queue) {
    int i;

    if (queue) {
        for (i = 0; i < queue->count; i++) {
            ueum_queue_pop(queue);
        }
    }
}

bool ueum_queue_push(ueum_queue *queue, void *data) {
    bool result;

    ei_check_parameter_or_return(queue);
    ei_check_parameter_or_return(data);

    ueum_thread_mutex_lock(queue->mutex);

    result = ueum_queue_push_internal(queue, data, false);

    ueum_thread_mutex_unlock(queue->mutex);

    return result;
}

bool ueum_queue_push_wait(ueum_queue *queue, void *data) {
    bool result;

    ei_check_parameter_or_return(queue);
    ei_check_parameter_or_return(data);

    ueum_thread_mutex_lock(queue->mutex);

    result = ueum_queue_push_internal(queue, data, true);

    ueum_thread_mutex_unlock(queue->mutex);

    return result;
}

bool ueum_queue_pop(ueum_queue *queue) {
    ei_check_parameter_or_return(queue);

    ueum_thread_mutex_lock(queue->mutex);

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
            ueum_safe_free(queue->front);
            queue->front = queue->front1;
        }
        else {
            if (queue->user_free_func) {
                queue->user_free_func(queue->front->data);
            } else {
                queue->front->data = NULL;
            }
            ueum_safe_free(queue->front);
            queue->front = NULL;
            queue->rear = NULL;
        }
        queue->count--;
    }

    ueum_thread_mutex_unlock(queue->mutex);

    ueum_thread_cond_signal(queue->write_cond);

    return true;
}

int ueum_queue_size(ueum_queue *queue) {
    int size;

    if (!queue) {
        ei_stacktrace_push_code(ERRORINTERCEPTOR_INVALID_PARAMETER);
        return -1;
    }

    ueum_thread_mutex_lock(queue->mutex);

    size = queue->count;

    ueum_thread_mutex_unlock(queue->mutex);

    return size;
}

void *ueum_queue_front(ueum_queue *queue) {
    void *result;

    ei_check_parameter_or_return(queue);

    ueum_thread_mutex_lock(queue->mutex);

    result = ueum_queue_front_internal(queue, false);

    ueum_thread_mutex_unlock(queue->mutex);

    return result;
}

void *ueum_queue_front_wait(ueum_queue *queue) {
    void *result;

    ei_check_parameter_or_return(queue);

    ueum_thread_mutex_lock(queue->mutex);

    result = ueum_queue_front_internal(queue, true);

    ueum_thread_mutex_unlock(queue->mutex);

    return result;
}

bool ueum_queue_empty(ueum_queue *queue) {
    bool result;

    ei_check_parameter_or_return(queue);

    ueum_thread_mutex_lock(queue->mutex);

    result = (queue->front == NULL) && (queue->rear == NULL);

    ueum_thread_mutex_unlock(queue->mutex);

    return result;
}

bool ueum_queue_print(ueum_queue *queue, FILE *fd) {
    bool result;

    ei_check_parameter_or_return(queue);
    ei_check_parameter_or_return(fd);

    ueum_thread_mutex_lock(queue->mutex);

    result = false;
    queue->front1 = queue->front;

    if ((queue->front1 == NULL) && (queue->rear == NULL)) {
        goto end;
    }

    if (queue->user_print_func == NULL) {
        ei_logger_warn("No print func specified by user");
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
    ueum_thread_mutex_unlock(queue->mutex);
    return result;
}

bool ueum_queue_set_print_func(ueum_queue *queue, void (*print_func)(void *data, FILE *fd)) {
    ei_check_parameter_or_return(queue);
    ei_check_parameter_or_return(print_func);

    queue->user_print_func = print_func;

    return true;
}

static bool ueum_queue_push_internal(ueum_queue *queue, void *data, bool wait) {
    (void)wait;
    /*if (queue->count == queue->capacity && wait) {
        while (queue->count == queue->capacity) {
            ueum_thread_cond_wait(queue->write_cond, queue->mutex);
        }
    } else if (queue->count == queue->capacity) {
        ei_stacktrace_push_msg("Max capacity is reached");
        return false;
    }*/

    if (queue->rear == NULL) {
        ueum_safe_alloc(queue->rear, struct ueum_queue_node, 1);
        queue->rear->ptr = NULL;
        if (queue->user_alloc_func) {
            queue->rear->data = queue->user_alloc_func(data);
        } else {
            queue->rear->data = data;
        }
        queue->front = queue->rear;
    }
    else {
        ueum_safe_alloc(queue->temp, struct ueum_queue_node, 1);
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

    ueum_thread_cond_signal(queue->read_cond);

    return true;
}

static void *ueum_queue_front_internal(ueum_queue *queue, bool wait) {
    void *result;

    result = NULL;

    if (wait && queue->count == 0) {
        ueum_thread_cond_wait(queue->read_cond, queue->mutex);
    } else if (queue->count == 0) {
        ei_stacktrace_push_msg("Queue is empty");
        return NULL;
    }

    if ((queue->front != NULL) && (queue->rear != NULL)) {
        result = queue->front->data;
    }

    return result;
}
