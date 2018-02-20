#ifndef UNKNOWNECHO_PROTOCOL_H
#define UNKNOWNECHO_PROTOCOL_H

#include <unknownecho/bool.h>
#include <unknownecho/protocol/global_context.h>
#include <unknownecho/protocol/channel.h>

unsigned short int ue_protocol_establish(ue_global_context *global_context, ue_channel *channel);

bool ue_protocol_is_established(ue_global_context *global_context, unsigned short int channel_id);

bool ue_protocol_start(ue_global_context *global_context, unsigned short int channel_id);

void ue_protocol_wait(ue_global_context *global_context);

void ue_protocol_stop_signal(ue_global_context *global_context, unsigned short int channel_id);

void ue_protocol_stop(ue_global_context *global_context, unsigned short int channel_id);

bool ue_protocol_is_communicating(ue_global_context *global_context, unsigned short int channel_id);

#endif
