#ifndef UNKNOWNECHO_RELAY_RECEIVED_MESSAGE_H
#define UNKNOWNECHO_RELAY_RECEIVED_MESSAGE_H

#include <unknownecho/protocol/api/relay/relay_received_message_struct.h>

ue_relay_received_message *ue_relay_received_message_create_empty();

void ue_relay_received_message_destroy(ue_relay_received_message *received_message);

#endif
