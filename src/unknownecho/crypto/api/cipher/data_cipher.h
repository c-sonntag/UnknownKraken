#ifndef UNKNOWNECHO_DATA_CIPHER_H
#define UNKNOWNECHO_DATA_CIPHER_H

#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/bool.h>

#include <stddef.h>

bool cipher_plain_data(unsigned char *plain_data, size_t plain_data_size, ue_public_key *public_key, ue_private_key *private_key, unsigned char **cipher_data, size_t *cipher_data_size, ue_sym_key *key);

bool decipher_cipher_data(unsigned char *cipher_data, size_t cipher_data_size, ue_private_key *private_key, ue_public_key *public_key, unsigned char **plain_data, size_t *plain_data_size);

#endif
