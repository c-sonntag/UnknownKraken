#ifndef UNKNOWNECHO_THREAD_RESULT_H
#define UNKNOWNECHO_THREAD_RESULT_H

#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/bool.h>

typedef struct {
    ue_thread_id *ti;
    void *result;
} ue_thread_result;

#define THREAD_RESULTS_MAX 10

ue_thread_result ue_thread_results[THREAD_RESULTS_MAX];

void ue_thread_results_init();

bool ue_thread_results_is_initialized();

bool ue_thread_result_exists(ue_thread_id *ti);

void ue_thread_result_add(ue_thread_id *ti);

void ue_thread_result_remove(ue_thread_id *ti);

void ue_thread_result_set(ue_thread_id *ti, void *result);

void *ue_thread_result_get(ue_thread_id *ti);

#endif
