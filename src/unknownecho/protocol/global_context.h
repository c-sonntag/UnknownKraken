#ifndef UNKNOWNECHO_GLOBAL_CONTEXT_H
#define UNKNOWNECHO_GLOBAL_CONTEXT_H

#include <unknownecho/protocol/channel.h>
#include <unknownecho/thread/thread_id_struct.h>

#define UNKNOWNECHO_CHANNELS_MAX 5

typedef struct {
    ue_channel **channels;
    unsigned short int channels_number;
    ue_thread_id **thread_channels;
} ue_global_context;

ue_global_context *ue_global_context_create();

void ue_global_context_destroy(ue_global_context *global_context);

#endif
