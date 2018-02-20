#include <unknownecho/thread/thread.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/check_parameter.h>

#include <errno.h>

ue_thread_id *ue_thread_create(void *function, void *arg) {
    ue_thread_id *ti;
    #if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
    #endif

    ue_check_parameter_or_return(function);

    ue_safe_alloc(ti, ue_thread_id, 1);

    #if defined(_WIN32) || defined(_WIN64)
        if (!(ti->id = CreateThread(NULL, 0, function, arg, 0, NULL)) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return NULL;
        }
        ue_thread_results_add(ti);
    #else
        _Pragma("GCC diagnostic push")
        _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
            if (pthread_create(&ti->id, NULL, (void *(*)(void *))function, arg) != 0) {
                ue_stacktrace_push_errno();
                ue_safe_free(ti);
                return NULL;
            }
        _Pragma("GCC diagnostic pop")
    #endif

    return ti;
}

bool ue_thread_join(ue_thread_id *ti, void **result) {
    #if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
        DWORD r;
    #else
        int r;
    #endif

    ue_check_parameter_or_return(ti);

    #if defined(_WIN32) || defined(_WIN64)
        r = WaitForSingleObject(ti->id, INFINITE);
        if (r == WAIT_FAILED) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return false;
        }
        else if (r == WAIT_OBJECT_0) {
            if (ue_thread_results_is_unitialized())
            {
                *result = ue_thread_result_get(ti);
            }
        }
    #else
        if ((r = pthread_join(ti->id, &(*result))) != 0) {
            if (errno != 0) {
                ue_stacktrace_push_errno();
            } else {
                if (r == EDEADLK) {
                    ue_logger_error("A deadlock was detected");
                    ue_stacktrace_push_msg("A deadlock was detected");
                } else if (r == EINVAL) {
                    ue_logger_warn("Thread is not joinable or another thread is already waiting to join with this thread");
                    return true;
                } else if (r == ESRCH) {
                    ue_logger_error("No thread with the ID thread could be found");
                    ue_stacktrace_push_msg("No thread with the ID thread could be found");
                }
            }
            return false;
        }
    #endif

    return true;
}

bool thread_detach(ue_thread_id *ti) {
    #if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
    #endif

    ue_check_parameter_or_return(ti);

    #if defined(_WIN32) || defined(_WIN64)
        if (!CloseHandle(ti->id)) {
            ue_get_last_werror(error_buffer);pth
            ue_stacktrace_push_msg(error_buffer);
            return false;
        }
    #else
        if (!pthread_detach(ti->id) != 0) {
            ue_stacktrace_push_errno();
            return false;
        }
    #endif

    return true;
}

bool ue_thread_cancel(ue_thread_id *ti) {
    #if defined(__unix__)
        pthread_cancel(ti->id);
        return true;
    #endif
    ue_stacktrace_push_msg("Not implemented for this OS");
    return false;
}
