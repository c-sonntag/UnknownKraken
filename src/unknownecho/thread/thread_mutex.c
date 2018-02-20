#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/system/alloc.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <unknownecho/errorHandling/error.h>
#endif

#include <errno.h>

/*
 * http://preshing.com/20111124/always-use-a-lightweight-mutex/
 */

ue_thread_mutex *ue_thread_mutex_create() {
    ue_thread_mutex *m;
    #if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
    #endif

    ue_safe_alloc(m, ue_thread_mutex, 1);

    #if defined(_WIN32) || defined(_WIN64)
        if (!(m->lock = CreateMutex(NULL, FALSE, NULL))) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            ue_safe_free(m);
            return NULL;
        }
    #else
        if (pthread_mutex_init(&m->lock, NULL) != 0) {
            ue_safe_free(m);
            ue_stacktrace_push_errno();
            return NULL;
        }
    #endif

    return m;
}

bool ue_thread_mutex_destroy(ue_thread_mutex *m) {
    bool state;
    #ifdef _WIN32
        char *error_buffer;
    #endif

    if (!m) {
        return true;
    }

    state = true;

    #if defined(_WIN32) || defined(_WIN64)
        if (m->lock) {
            if (!CloseHandle(m->lock)) {
                ue_get_last_werror(error_buffer);
                ue_stacktrace_push_msg(error_buffer);
                ue_safe_free(error_buffer);
                state = false;
            }
        }
    #else
        if (pthread_mutex_destroy(&m->lock) != 0) {
            ue_stacktrace_push_errno();
            state = false;
        }
    #endif

    ue_safe_free(m);

    return state;
}

bool ue_thread_mutex_lock(ue_thread_mutex *m) {
    #if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
    #endif

    ue_check_parameter_or_return(m)

    #if defined(_WIN32) || defined(_WIN64)
        if (WaitForSingleObject(m->lock, INFINITE) == WAIT_FAILED) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return false;
        }
    #else
        if (pthread_mutex_lock(&m->lock) != 0) {
            ue_logger_debug("errno value : %d", errno);
            ue_stacktrace_push_errno();
            return false;
        }
    #endif

    return true;
}

bool ue_thread_mutex_unlock(ue_thread_mutex *m) {
    #if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
    #endif

    ue_check_parameter_or_return(m);

    #if defined(_WIN32) || defined(_WIN64)
        if (!ReleaseMutex(m->lock)) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return false;
        }
    #else
        if (pthread_mutex_unlock(&m->lock) != 0) {
            ue_stacktrace_push_errno();
            return false;
        }
    #endif

    return true;
}
