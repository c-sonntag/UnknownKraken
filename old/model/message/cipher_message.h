#ifndef UNKNOWNECHO_CIPHER_MESSAGE_H
#define UNKNOWNECHO_CIPHER_MESSAGE_H

#include <unknownecho/model/entity/plain_message_struct.h>
#include <unknownecho/model/entity/cipher_message_struct.h>
#include <unknownecho/model/manager/pgp_keystore_manager_struct.h>

#include <stddef.h>

ue_cipher_message *ue_message_build_encrypted_as_client(ue_pgp_keystore_manager *manager, ue_plain_message *message);

unsigned char *ue_cipher_message_to_data(ue_cipher_message *cmsg, size_t *message_size);

void ue_cipher_message_destroy(ue_cipher_message *message);

void ue_cipher_message_clean_up(ue_cipher_message *cmsg);

#endif
