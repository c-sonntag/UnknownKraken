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

#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

int main() {
    uk_utils_queue *queue;
    const char *data;
    void *element;
    
    queue = NULL;
    data = "Hello world !";

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    uk_utils_logger_info("Creating an empty queue");
    if ((queue = uk_utils_queuk_ue_create()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create new empty queue");
        goto clean_up;
    }

    uk_utils_logger_info("Pushing a new element to the queue");
    if (!uk_utils_queuk_ue_push(queue, (void *)data)) {
        uk_utils_stacktrace_push_msg("Failed to push data to the queue");
        goto clean_up;
    }

    uk_utils_logger_info("Checking if the queue is empty");
    if (uk_utils_queuk_ue_empty(queue)) {
        uk_utils_stacktrace_push_msg("The queue is empty but it shouldn't");
        goto clean_up;
    }

    uk_utils_logger_info("The queue isn't empty and contains %d element", uk_utils_queuk_ue_size(queue));

    uk_utils_logger_info("Get the front element of the queue");
    if ((element = uk_utils_queuk_ue_front(queue)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to get the front element from the queue");
        goto clean_up;
    }

    uk_utils_logger_info("The element of the queue contains: %s", (char *)element);

    if (!uk_utils_queuk_ue_pop(queue)) {
        uk_utils_stacktrace_push_msg("Failed to pop the queue");
        goto clean_up;
    }

clean_up:
    uk_utils_queuk_ue_destroy(queue);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return 0;
}
