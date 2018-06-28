#ifndef UNKNOWNECHO_PROTOCOL_ID_H
#define UNKNOWNECHO_PROTOCOL_ID_H

#include <ueum/ueum.h>

typedef enum {
    UNKNOWNECHO_PROTOCOL_ID_CHANNEL = 0,
    UNKNOWNECHO_PROTOCOL_ID_RELAY
} ue_protocol_id;

bool ue_protocol_id_is_valid(int id);

#endif
