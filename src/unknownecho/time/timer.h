#ifndef UNKNOWNECHO_TIMER_H
#define UNKNOWNECHO_TIMER_H

#include <unknownecho/time/timer_struct.h>
#include <unknownecho/time/timer_measure_struct.h>
#include <unknownecho/time/timer_measure.h>
#include <unknownecho/time/clock_time_posix.h>
#include <unknownecho/bool.h>
#include <unknownecho/thread/thread_storage.h>

#include <time.h>

ue_timer *ue_timer_create_empty();

void ue_timer_destroy(ue_timer *tm);

bool ue_timer_start_impl(ue_timer *tm, unsigned int id, int timestamp);

bool ue_timer_stop_impl(ue_timer *tm, unsigned int id, int timestamp);

void ue_timer_average_impl(ue_timer *tm, unsigned int id, double *result);

bool ue_timer_average_print_impl(ue_timer *tm, unsigned int id, char *prefix_message);

void ue_timer_total_impl(ue_timer *tm, unsigned int id, double *result);

bool ue_timer_total_print_impl(ue_timer *tm, unsigned int id, char *prefix_message);

bool ue_timer_set_unity_impl(ue_timer *tm, unsigned int id, char *unity);

#define ue_timer_set_unity(id, unity) \
	ue_timer_set_unity_impl(ue_thread_storage_get_timer(), id, unity); \

#define ue_timer_start(id) \
	ue_timer_start_impl(ue_thread_storage_get_timer(), id, ue_get_posix_clock_time()); \

#define ue_timer_stop(id) \
	ue_timer_stop_impl(ue_thread_storage_get_timer(), id, ue_get_posix_clock_time()); \

#define ue_timer_average(id, result) \
	ue_timer_average_impl(ue_thread_storage_get_timer(), id, &result); \

#define ue_timer_average_print(id, message) \
	ue_timer_average_print_impl(ue_thread_storage_get_timer(), id, message); \

#define ue_timer_total(id, result) \
	ue_timer_total_impl(ue_thread_storage_get_timer(), id, &result); \

#define ue_timer_total_print(id, message) \
	ue_timer_total_print_impl(ue_thread_storage_get_timer(), id, message); \

#endif
