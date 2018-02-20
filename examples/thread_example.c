#include <unknownecho/init.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/time/timer.h>
#include <unknownecho/system/alloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

typedef enum {
    WORKING_STATE,
    FREE_STATE
} processing_state;

ue_thread_mutex *locker;
processing_state state = FREE_STATE;
int tirage_dans_le_disque, nombre_tirages, threads_number;
unsigned int *random_states;

double double_rand(unsigned int *random_state, double min, double max) {
    double scale = rand_r(random_state) / (double) RAND_MAX;
    return min + scale * (max - min);
}

void *tirage_dans_le_disque_callback(void *param) {
    double x, y;
    int i, tirage_dans_le_disque_local;
    unsigned int *random_state;

    tirage_dans_le_disque_local = 0;
    random_state = param;
    /* XOR multiple values together to get a semi-unique seed */
    *random_state = time(NULL) ^ getpid() ^ pthread_self();

    for (i = 0; i < nombre_tirages / threads_number; i++) {
        x = double_rand(random_state, 0.0, 1.0);
        y = double_rand(random_state, 0.0, 1.0);


        if (x * x + y * y <= 1) {
            tirage_dans_le_disque_local++;
        }
    }

    ue_thread_mutex_lock(locker);
    tirage_dans_le_disque += tirage_dans_le_disque_local;
    ue_thread_mutex_unlock(locker);

    pthread_exit((void*) 0);
}

int main(int argc, char **argv) {
    int i;
    ue_thread_id **threads;

    tirage_dans_le_disque = 0;
    nombre_tirages = 200000000;
    //nombre_tirages = 20000000;
    //nombre_tirages = 1000000;
    locker = NULL;
    threads = NULL;

    if (argc > 1) {
        threads_number = atoi(argv[1]);
    } else {
        threads_number = 10;
    }

    ue_init();
    ue_logger_info("UnknownEchoLib is correctly initialized");

    ue_safe_alloc(threads, ue_thread_id *, threads_number);
    ue_safe_alloc(random_states, unsigned int, threads_number);

    locker = ue_thread_mutex_create();

    ue_timer_start(1);

    for (i = 0; i < threads_number; i++) {
        _Pragma("GCC diagnostic push")
        _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
            threads[i] = ue_thread_create((void *)tirage_dans_le_disque_callback, &random_states[i]);
        _Pragma("GCC diagnostic pop")
    }

    for (i = 0; i < threads_number; i++) {
        ue_thread_join(threads[i], NULL);
    }

    ue_timer_stop(1);

    printf("tirage_dans_le_disque : %d\n", tirage_dans_le_disque);

    ue_timer_total_print(1, "tirages dans le disque");

    ue_thread_mutex_destroy(locker);

    for (i = 0; i < threads_number; i++) {
        ue_safe_free(threads[i]);
    }
    ue_safe_free(threads);

    ue_safe_free(random_states);

    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
