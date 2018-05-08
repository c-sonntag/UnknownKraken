#ifndef UNKNOWNECHO_RELAY_PLAIN_MESSAGE_H
#define UNKNOWNECHO_RELAY_PLAIN_MESSAGE_H

#include <unknownecho/protocol/api/relay/relay_plain_message_struct.h>

ue_relay_plain_message *ue_relay_plain_message_create_empty();

void ue_relay_plain_message_destroy(ue_relay_plain_message *plain_message);

#endif
