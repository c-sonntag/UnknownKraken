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

#include <uk/utils/container/queue.h>
#include <uk/utils/safe/safe_alloc.h>
#include <uk/utils/ei.h>

#include <stdio.h>


static bool uk_utils_queuk_ue_push_internal(uk_utils_queue *queue, void *data, bool wait);

static void *uk_utils_queuk_ue_front_internal(uk_utils_queue *queue, bool wait);


uk_utils_queue *uk_utils_queuk_ue_create() {
    uk_utils_queue *queue;

    queue = NULL;

    uk_utils_safe_alloc(queue, uk_utils_queue, 1);
    queue->front = queue->rear = NULL;
    queue->count = 0;
    queue->user_print_func = NULL;
    queue->mutex = uk_utils_thread_mutex_create();
    queue->read_cond = uk_utils_thread_cond_create();
    queue->write_cond = uk_utils_thread_cond_create();
    queue->user_alloc_func = NULL;
    queue->user_free_func = NULL;

    return queue;
}

uk_utils_queue *uk_utils_queuk_ue_create_mem(void *(*alloc_func)(void *data), void (*free_func)(void *data)) {
    uk_utils_queue *queue;

    uk_utils_check_parameter_or_return(alloc_func);
    uk_utils_check_parameter_or_return(free_func);

    queue = uk_utils_queuk_ue_create();
    queue->user_alloc_func = alloc_func;
    queue->user_free_func = free_func;

    return queue;
}

void uk_utils_queuk_ue_destroy(uk_utils_queue *queue) {
    int i;

    if (queue) {
        for (i = 0; i < queue->count; i++) {
            uk_utils_queuk_ue_pop(queue);
        }

        uk_utils_thread_mutex_destroy(queue->mutex);
        uk_utils_thread_cond_destroy(queue->read_cond);
        uk_utils_thread_cond_destroy(queue->write_cond);

        uk_utils_safe_free(queue);
    }
}

void uk_utils_queuk_ue_clean_up(uk_utils_queue *queue) {
    int i;

    if (queue) {
        for (i = 0; i < queue->count; i++) {
            uk_utils_queuk_ue_pop(queue);
        }
    }
}

bool uk_utils_queuk_ue_push(uk_utils_queue *queue, void *data) {
    bool result;

    uk_utils_check_parameter_or_return(queue);
    uk_utils_check_parameter_or_return(data);

    uk_utils_thread_mutex_lock(queue->mutex);

    result = uk_utils_queuk_ue_push_internal(queue, data, false);

    uk_utils_thread_mutex_unlock(queue->mutex);

    return result;
}

bool uk_utils_queuk_ue_push_wait(uk_utils_queue *queue, void *data) {
    bool result;

    uk_utils_check_parameter_or_return(queue);
    uk_utils_check_parameter_or_return(data);

    uk_utils_thread_mutex_lock(queue->mutex);

    result = uk_utils_queuk_ue_push_internal(queue, data, true);

    uk_utils_thread_mutex_unlock(queue->mutex);

    return result;
}

bool uk_utils_queuk_ue_pop(uk_utils_queue *queue) {
    uk_utils_check_parameter_or_return(queue);

    uk_utils_thread_mutex_lock(queue->mutex);

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
            uk_utils_safe_free(queue->front);
            queue->front = queue->front1;
        }
        else {
            if (queue->user_free_func) {
                queue->user_free_func(queue->front->data);
            } else {
                queue->front->data = NULL;
            }
            uk_utils_safe_free(queue->front);
            queue->front = NULL;
            queue->rear = NULL;
        }
        queue->count--;
    }

    uk_utils_thread_mutex_unlock(queue->mutex);

    uk_utils_thread_cond_signal(queue->write_cond);

    return true;
}

int uk_utils_queuk_ue_size(uk_utils_queue *queue) {
    int size;

    if (!queue) {
        uk_utils_stacktrace_push_code(UnknownKrakenUtils_INVALID_PARAMETER);
        return -1;
    }

    uk_utils_thread_mutex_lock(queue->mutex);

    size = queue->count;

    uk_utils_thread_mutex_unlock(queue->mutex);

    return size;
}

void *uk_utils_queuk_ue_front(uk_utils_queue *queue) {
    void *result;

    uk_utils_check_parameter_or_return(queue);

    uk_utils_thread_mutex_lock(queue->mutex);

    result = uk_utils_queuk_ue_front_internal(queue, false);

    uk_utils_thread_mutex_unlock(queue->mutex);

    return result;
}

void *uk_utils_queuk_ue_front_wait(uk_utils_queue *queue) {
    void *result;

    uk_utils_check_parameter_or_return(queue);

    uk_utils_thread_mutex_lock(queue->mutex);

    result = uk_utils_queuk_ue_front_internal(queue, true);

    uk_utils_thread_mutex_unlock(queue->mutex);

    return result;
}

bool uk_utils_queuk_ue_empty(uk_utils_queue *queue) {
    bool result;

    uk_utils_check_parameter_or_return(queue);

    uk_utils_thread_mutex_lock(queue->mutex);

    result = (queue->front == NULL) && (queue->rear == NULL);

    uk_utils_thread_mutex_unlock(queue->mutex);

    return result;
}

bool uk_utils_queuk_ue_print(uk_utils_queue *queue, FILE *fd) {
    bool result;

    uk_utils_check_parameter_or_return(queue);
    uk_utils_check_parameter_or_return(fd);

    uk_utils_thread_mutex_lock(queue->mutex);

    result = false;
    queue->front1 = queue->front;

    if ((queue->front1 == NULL) && (queue->rear == NULL)) {
        goto end;
    }

    if (queue->user_print_func == NULL) {
        uk_utils_logger_warn("No print func specified by user");
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
    uk_utils_thread_mutex_unlock(queue->mutex);
    return result;
}

bool uk_utils_queuk_ue_set_print_func(uk_utils_queue *queue, void (*print_func)(void *data, FILE *fd)) {
    uk_utils_check_parameter_or_return(queue);
    uk_utils_check_parameter_or_return(print_func);

    queue->user_print_func = print_func;

    return true;
}

static bool uk_utils_queuk_ue_push_internal(uk_utils_queue *queue, void *data, bool wait) {
    (void)wait;
    /*if (queue->count == queue->capacity && wait) {
        while (queue->count == queue->capacity) {
            uk_utils_thread_cond_wait(queue->write_cond, queue->mutex);
        }
    } else if (queue->count == queue->capacity) {
        uk_utils_stacktrace_push_msg("Max capacity is reached");
        return false;
    }*/

    if (queue->rear == NULL) {
        uk_utils_safe_alloc(queue->rear, struct uk_utils_queuk_ue_node, 1);
        queue->rear->ptr = NULL;
        if (queue->user_alloc_func) {
            queue->rear->data = queue->user_alloc_func(data);
        } else {
            queue->rear->data = data;
        }
        queue->front = queue->rear;
    }
    else {
        uk_utils_safe_alloc(queue->temp, struct uk_utils_queuk_ue_node, 1);
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

    uk_utils_thread_cond_signal(queue->read_cond);

    return true;
}

static void *uk_utils_queuk_ue_front_internal(uk_utils_queue *queue, bool wait) {
    void *result;

    result = NULL;

    if (wait && queue->count == 0) {
        uk_utils_thread_cond_wait(queue->read_cond, queue->mutex);
    } else if (queue->count == 0) {
        uk_utils_stacktrace_push_msg("Queue is empty");
        return NULL;
    }

    if ((queue->front != NULL) && (queue->rear != NULL)) {
        result = queue->front->data;
    }

    return result;
}
