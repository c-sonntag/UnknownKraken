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

#include <unknownecho/container/queue.h>
#include <unknownecho/init.h>
#include <unknownecho/alloc.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/time/sleep.h>

#include <stdio.h>

typedef struct {
    int x, y;
} object;

void object_print(void *data, FILE *fd) {
    object *obj = (object *)data;
    fprintf(fd, "obj->x:%d ; obj->y:%d\n", obj->x, obj->y);
}

ue_queue *queue;
object *obj1, *obj2;

void writer(void *parameter) {
    int i;

    for (i = 0; i < 10; i++) {
        printf("i : %d\n", i);
        printf("Size : %d\n", ue_queue_size(queue));
        ue_queue_push_wait(queue, obj1);
        printf("\n");
        ue_millisleep(100);
    }
}

void reader(void *parameter) {
    int size, j;

    for (j = 0; j < 10; j++) {
        printf("j : %d\n", j);
        size = ue_queue_size(queue);
        printf("Size : %d\n", size);
        if (size > 0) {
            object_print(ue_queue_front_wait(queue), stdout);
            ue_queue_pop(queue);
        }
        printf("\n");
        ue_millisleep(100);
    }
}

int main() {
    ue_thread_id *reader_id, *writer_id;

    queue = NULL;
    obj1 = NULL;
    obj2 = NULL;
    reader_id = NULL;
    writer_id = NULL;

    ue_init();

    queue = ue_queue_create();
    ue_queue_set_print_func(queue, object_print);

    ue_safe_alloc(obj1, object, 1);
    obj1->x = 10;
    obj1->y = 15;

    ue_safe_alloc(obj2, object, 1);
    obj2->x = 20;
    obj2->y = 25;

    ue_queue_print(queue, stdout);

    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
        writer_id = ue_thread_create((void *)writer, NULL);
        reader_id = ue_thread_create((void *)reader, NULL);
    _Pragma("GCC diagnostic pop")

    ue_thread_join(writer_id, NULL);
    ue_thread_join(reader_id, NULL);

    printf("Is empty : %d\n", ue_queue_empty(queue));

    ue_safe_free(obj1);

    ue_queue_destroy(queue);

    ue_safe_free(obj2);

    ue_uninit();

    return 0;
}
