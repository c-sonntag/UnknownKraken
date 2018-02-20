#ifndef UNKNOWNECHO_THREAD_COND_H
#define UNKNOWNECHO_THREAD_COND_H

#include <unknownecho/bool.h>
#include <unknownecho/thread/thread_mutex.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#elif defined(__unix__)
    #include <pthread.h>
#endif

typedef struct {
	#if defined(_WIN32) || defined(_WIN64)
	#elif defined(__unix__)
	    pthread_cond_t data;
	#endif
} ue_thread_cond;

ue_thread_cond *ue_thread_cond_create();

void ue_thread_cond_destroy(ue_thread_cond *cond);

bool ue_thread_cond_wait(ue_thread_cond *cond, ue_thread_mutex *mutex);

bool ue_thread_cond_signal(ue_thread_cond *cond);

bool ue_thread_cond_broadcast(ue_thread_cond *cond);

#endif
