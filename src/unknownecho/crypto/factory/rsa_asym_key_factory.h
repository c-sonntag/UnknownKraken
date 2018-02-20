#ifndef UNKNOWNECHO_RSA_ASYM_KEY_FACTORY_H
#define UNKNOWNECHO_RSA_ASYM_KEY_FACTORY_H

#include <unknownecho/crypto/api/key/asym_key.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>

ue_asym_key *ue_rsa_asym_key_create(int bits);

ue_public_key *ue_rsa_public_key_create_pk_from_file(char *file_path);

ue_private_key *ue_rsa_private_key_create_sk_from_file(char *file_path);

ue_asym_key *ue_rsa_asym_key_create_from_files(char *pk_file_path, char *sk_file_path);

ue_public_key *ue_rsa_public_key_from_x509_certificate(ue_x509_certificate *certificate);

ue_private_key *ue_rsa_private_key_from_key_certificate(const char *file_name);

#endif
