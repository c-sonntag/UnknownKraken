#ifndef UNKNOWNECHO_X509_CERTIFICATE_FACTORY_H
#define UNKNOWNECHO_X509_CERTIFICATE_FACTORY_H

#include <unknownecho/bool.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/private_key.h>

bool ue_x509_certificate_generate_self_signed_ca(char *C, char *CN, ue_x509_certificate **certificate, ue_private_key **private_key);

bool ue_x509_certificate_generate_signed(ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key,
    char *C, char *CN, ue_x509_certificate **certificate, ue_private_key **private_key);

#endif
