#ifndef UNKNOWNECHO_DECIPHER_MESSAGE_H
#define UNKNOWNECHO_DECIPHER_MESSAGE_H

#include <unknownecho/model/entity/plain_message_struct.h>
#include <unknownecho/model/entity/cipher_message_struct.h>
#include <unknownecho/model/manager/pgp_keystore_manager_struct.h>

#include <stddef.h>

ue_plain_message *ue_message_build_decrypted_as_client(ue_pgp_keystore_manager *manager, ue_cipher_message *cmsg);

ue_plain_message *ue_message_build_decrypted_as_server(ue_pgp_keystore_manager *manager, ue_cipher_message *cmsg);

ue_cipher_message *ue_data_to_cipher_message(unsigned char *message_content, size_t message_size);

#endif
