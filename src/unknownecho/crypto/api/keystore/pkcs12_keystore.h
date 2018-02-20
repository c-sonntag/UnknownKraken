#ifndef UNKNOWNECHO_PKCS12_KEYSTORE_H
#define UNKNOWNECHO_PKCS12_KEYSTORE_H

#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

typedef struct {
    ue_x509_certificate *certificate;
    ue_private_key *private_key;
    ue_x509_certificate **other_certificates;
    int other_certificates_number;
    char *friendly_name;
} ue_pkcs12_keystore;

ue_pkcs12_keystore *ue_pkcs12_keystore_create(ue_x509_certificate *certificate, ue_private_key *private_key, char *friendly_name);

ue_pkcs12_keystore *ue_pkcs12_keystore_load(const char *file_name, char *passphrase, char *pem_passphrase);

void ue_pkcs12_keystore_destroy(ue_pkcs12_keystore *keystore);

bool ue_pkcs12_keystore_add_certificate(ue_pkcs12_keystore *keystore, ue_x509_certificate *certificate);

bool ue_pkcs12_keystore_add_certificates_bundle(ue_pkcs12_keystore *keystore, const char *file_name, const char *passphrase);

bool ue_pkcs12_keystore_remove_certificate_from_CN(ue_pkcs12_keystore *keystore, const char *file_name);

bool ue_pkcs12_keystore_write(ue_pkcs12_keystore *keystore, const char *file_name, char *passphrase, char *pem_passphrase);

#endif
