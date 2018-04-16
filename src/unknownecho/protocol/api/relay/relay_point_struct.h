#ifndef UNKNOWNECHO_RELAY_POINT_STRUCT_H
#define UNKNOWNECHO_RELAY_POINT_STRUCT_H

typedef struct {
    const char *current_host;
    const char *next_host;
    const char *communication_type;
} ue_relay_point;

#endif
