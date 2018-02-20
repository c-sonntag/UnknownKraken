#ifndef UNKNOWNECHO_THREAD_STORAGE_H
#define UNKNOWNECHO_THREAD_STORAGE_H

#include <unknownecho/bool.h>
#include <unknownecho/time/timer_struct.h>
#include <unknownecho/errorHandling/stacktrace_struct.h>

bool ue_thread_storage_init();

void ue_thread_storage_uninit();

bool ue_thread_storage_append_to_be_deleted_data(void *data);

ue_stacktrace *ue_thread_storage_get_stacktrace();

ue_stacktrace **ue_thread_storage_get_all_stacktrace(int *number);

ue_stacktrace *ue_thread_storage_get_stacktrace_from_thread_id(long ue_thread_id);

ue_timer *ue_thread_storage_get_timer();

ue_timer **ue_thread_storage_get_all_timer(int *number);

bool ue_thread_storage_set_char_data(char *data);

char *ue_thread_storage_get_char_data();

bool ue_thread_storage_set_int_data(int data);

int ue_thread_storage_get_int_data();

#endif
