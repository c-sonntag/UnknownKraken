#ifndef UNKNOWNECHO_THREAD_MUTEX_H
#define UNKNOWNECHO_THREAD_MUTEX_H

#include <unknownecho/bool.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <pthread.h>
#endif

typedef struct {
    #if defined(_WIN32) || defined(_WIN64)
        /* HANDLE lock; */
        CRITICAL_SECTION lock;
    #else
        pthread_mutex_t lock;
    #endif
} ue_thread_mutex;

ue_thread_mutex *ue_thread_mutex_create();

bool ue_thread_mutex_destroy(ue_thread_mutex *m);

bool ue_thread_mutex_lock(ue_thread_mutex *m);

bool ue_thread_mutex_unlock(ue_thread_mutex *m);

#endif
