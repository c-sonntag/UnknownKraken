#ifndef UNKNOWNECHO_CRYPTO_METADATA_FACTORY_H
#define UNKNOWNECHO_CRYPTO_METADATA_FACTORY_H

#include <unknownecho/crypto/api/crypto_metadata.h>

ue_crypto_metadata *ue_crypto_metadata_create_default();

ue_crypto_metadata *ue_crypto_metadata_write_if_not_exist(const char *private_folder, const char *
    certificates_folder, const char *uid, const char *password);

#endif
