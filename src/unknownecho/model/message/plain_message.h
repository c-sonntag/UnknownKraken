#ifndef UNKNOWNECHO_PLAIN_MESSAGE_H
#define UNKNOWNECHO_PLAIN_MESSAGE_H

#include <unknownecho/model/entity/plain_message_struct.h>
#include <unknownecho/model/manager/pgp_keystore_manager_struct.h>

ue_plain_message *ue_plain_message_create_empty();

ue_plain_message *ue_plain_message_create(ue_pgp_keystore_manager *manager, char *dest_nickname, char *src_nickname, char *msg_content, char *message_type);

void ue_plain_message_destroy(ue_plain_message *message);

void ue_plain_message_clean_up(ue_plain_message *pmsg);

bool ue_plain_message_fill(ue_plain_message *pmsg, ue_pgp_keystore_manager *manager, char *dest_nickname, char *src_nickname, char *msg_content, char *message_type);

char *ue_plain_message_to_string(ue_plain_message *message);

char *ue_plain_message_header_to_string(ue_plain_message *message);

bool ue_plain_message_equals(ue_plain_message *pmsg1, ue_plain_message *pmsg2);

bool ue_plain_message_header_equals(ue_plain_message *pmsg1, ue_plain_message *pmsg2);

bool ue_plain_message_print(ue_plain_message *message);

#endif
