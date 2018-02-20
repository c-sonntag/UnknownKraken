#ifndef UNKNOWNECHO_RSA_SIGNER_FACTORY_H
#define UNKNOWNECHO_RSA_SIGNER_FACTORY_H

#include <unknownecho/crypto/api/signature/signer.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/key/asym_key.h>

ue_signer *ue_rsa_signer_create(ue_public_key *pk, ue_private_key *sk);

ue_signer *ue_rsa_signer_create_from_pair(ue_asym_key *akey);

#endif
