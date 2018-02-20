#ifndef UNKNOWNECHO_TIMER_MEASURE_STRUCT_H
#define UNKNOWNECHO_TIMER_MEASURE_STRUCT_H

typedef struct {
	unsigned int id;
	int *times_begin;
	int *times_end;
	int times_begin_number;
	int times_end_number;
	char *unity;
} ue_timer_measure;

#endif
