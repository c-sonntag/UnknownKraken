#ifndef UNKNOWNECHO_TIMER_STRUCT_H
#define UNKNOWNECHO_TIMER_STRUCT_H

#include <unknownecho/time/timer_measure.h>

typedef struct {
    ue_timer_measure **measures;
    unsigned int measures_number;
    long ue_thread_id;
} ue_timer;

#endif
