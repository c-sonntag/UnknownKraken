#ifndef UNKNOWNECHO_SYM_ENCRYPTER_FACTORY_H
#define UNKNOWNECHO_SYM_ENCRYPTER_FACTORY_H

#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/api/key/sym_key.h>

ue_sym_encrypter *ue_sym_encrypter_aes_create(ue_sym_key *key);

ue_sym_encrypter *ue_sym_encrypter_default_create(ue_sym_key *key);

#endif
