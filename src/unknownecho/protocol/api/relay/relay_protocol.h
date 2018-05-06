#ifndef UNKNOWNECHO_RELAY_PROTOCOL_H
#define UNKNOWNECHO_RELAY_PROTOCOL_H

#include <unknownecho/protocol/api/relay/relay_protocol_context.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/bool.h>

ue_relay_protocol_context *ue_relay_protocol_init_from_string(const char *string);

ue_relay_protocol_context *ue_relay_protocol_init_from_route(ue_relay_step **steps, unsigned short int steps_number);

ue_relay_protocol_context *ue_relay_protocol_init_from_file(const char *file_path);

void ue_relay_protocol_destroy(ue_relay_protocol_context *context);

bool ue_relay_protocol_establish_dry_run(ue_relay_protocol_context *context);

bool ue_relay_protocol_establish(ue_relay_protocol_context *context);

bool ue_relay_protocol_close(ue_relay_protocol_context *context);

bool ue_relay_protocol_send(ue_relay_protocol_context *context);

bool ue_relay_protocol_receive(ue_relay_protocol_context *context);

#endif
