#ifndef UNKNOWNECHO_THREAD_ID_STRUCT_H
#define UNKNOWNECHO_THREAD_ID_STRUCT_H

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <pthread.h>
#endif

typedef struct {
    #if defined(_WIN32) || defined(_WIN64)
        HANDLE id;
    #else
        pthread_t id;
    #endif
} ue_thread_id;

#endif
