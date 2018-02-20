#include <unknownecho/thread/thread_result.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <string.h>

bool ue_thread_results_initialized = false;

void ue_thread_results_init() {
    unsigned short int i;

    memset(&ue_thread_results, 0, THREAD_RESULTS_MAX * sizeof(ue_thread_result));

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        memset(&ue_thread_results[i].ti, 0, sizeof(ue_thread_id));
        memset(&ue_thread_results[i].result, 0, sizeof(void *));
    }

    ue_thread_results_initialized = true;
}

bool ue_thread_results_is_initialized() {
    return ue_thread_results_initialized;
}

bool ue_thread_result_exists(ue_thread_id *ti) {
    if (!ue_thread_results_initialized) {
        return false;
    }

    unsigned short int i;

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        if (ue_thread_results[i].ti == ti) {
            return true;
        }
    }

    return false;
}

void ue_thread_result_add(ue_thread_id *ti) {
    unsigned short int i;

    if (!ue_thread_results_initialized || ue_thread_result_exists(ti)) {
        return;
    }

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        if (!ue_thread_results[i].ti) {
            ue_thread_results[i].ti = ti;
            break;
        }
    }
}

void ue_thread_result_remove(ue_thread_id *ti) {
    unsigned short int i;

    if (!ue_thread_results_initialized) {
        return;
    }

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        if (ue_thread_results[i].ti == ti) {
            ue_thread_results[i].ti = NULL;
            ue_thread_results[i].result = NULL;
            break;
        }
    }
}

void ue_thread_result_set(ue_thread_id *ti, void *result) {
    unsigned short int i;

    if (!ue_thread_results_initialized) {
        return;
    }

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        if (ue_thread_results[i].ti == ti) {
            ue_thread_results[i].result = result;
            break;
        }
    }
}

void *ue_thread_result_get(ue_thread_id *ti) {
    unsigned short int i;
    void *result;

    if (!ue_thread_results_initialized) {
        return NULL;
    }

    result = NULL;

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        if (ue_thread_results[i].ti == ti) {
            result = ue_thread_results[i].result;
            ue_thread_results[i].ti = NULL;
            ue_thread_results[i].result = NULL;
            break;
        }
    }

    return result;
}
