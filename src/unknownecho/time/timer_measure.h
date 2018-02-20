#ifndef UNKNOWNECHO_TIMER_MEASURE_H
#define UNKNOWNECHO_TIMER_MEASURE_H

#include <unknownecho/time/timer_measure_struct.h>
#include <unknownecho/bool.h>

ue_timer_measure *ue_timer_measure_create(unsigned int id);

void ue_timer_measure_destroy(ue_timer_measure *measure);

char *ue_timer_measure_get_unity(ue_timer_measure *measure);

bool ue_timer_measure_set_unity(ue_timer_measure *measure, char *unity);

bool ue_timer_measure_append_begin(ue_timer_measure *measure, int time);

bool ue_timer_measure_append_end(ue_timer_measure *measure, int time);

bool ue_timer_measure_average(ue_timer_measure *measure, double *result);

#endif
