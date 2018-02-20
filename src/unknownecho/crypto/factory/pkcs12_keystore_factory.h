#ifndef UNKNOWNECHO_PKCS12_KEYSTORE_FACTORY_H
#define UNKNOWNECHO_PKCS12_KEYSTORE_FACTORY_H

#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>

ue_pkcs12_keystore *ue_pkcs12_keystore_create_random(char *CN, char *friendly_name);

ue_pkcs12_keystore *ue_pkcs12_keystore_create_from_files(char *certificate_path, char *private_key_path, char *friendly_name);

#endif
