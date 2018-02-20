#ifndef UNKNOWNECHO_ASYM_ENCRYPTER_FACTORY_H
#define UNKNOWNECHO_ASYM_ENCRYPTER_FACTORY_H

#include <unknownecho/crypto/api/encryption/asym_encrypter.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>

ue_asym_encrypter *ue_asym_encrypter_rsa_pkcs1_create(ue_public_key *pk, ue_private_key *sk);

ue_asym_encrypter *ue_asym_encrypter_rsa_pkcs1_oaep_create(ue_public_key *pk, ue_private_key *sk);

ue_asym_encrypter *ue_asym_encrypter_default_create(ue_public_key *pk, ue_private_key *sk);

#endif
