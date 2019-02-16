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

#include <ueum/ueum.h>
#include <ei/ei.h>

int main() {
    ueum_queue *queue;
    const char *data;
    void *element;
    
    queue = NULL;
    data = "Hello world !";

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    ei_logger_info("Creating an empty queue");
    if ((queue = ueum_queue_create()) == NULL) {
        ei_stacktrace_push_msg("Failed to create new empty queue");
        goto clean_up;
    }

    ei_logger_info("Pushing a new element to the queue");
    if (!ueum_queue_push(queue, (void *)data)) {
        ei_stacktrace_push_msg("Failed to push data to the queue");
        goto clean_up;
    }

    ei_logger_info("Checking if the queue is empty");
    if (ueum_queue_empty(queue)) {
        ei_stacktrace_push_msg("The queue is empty but it shouldn't");
        goto clean_up;
    }

    ei_logger_info("The queue isn't empty and contains %d element", ueum_queue_size(queue));

    ei_logger_info("Get the front element of the queue");
    if ((element = ueum_queue_front(queue)) == NULL) {
        ei_stacktrace_push_msg("Failed to get the front element from the queue");
        goto clean_up;
    }

    ei_logger_info("The element of the queue contains: %s", (char *)element);

    if (!ueum_queue_pop(queue)) {
        ei_stacktrace_push_msg("Failed to pop the queue");
        goto clean_up;
    }

clean_up:
    ueum_queue_destroy(queue);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    ei_uninit();
    return 0;
}
