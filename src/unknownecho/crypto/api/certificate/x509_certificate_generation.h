#ifndef UNKNOWNECHO_X509_CERTFICATE_GENERATION_H
#define UNKNOWNECHO_X509_CERTFICATE_GENERATION_H

#include <unknownecho/bool.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_parameters.h>
#include <unknownecho/crypto/api/key/private_key.h>

bool ue_x509_certificate_generate(ue_x509_certificate_parameters *parameters, ue_x509_certificate **certificate, ue_private_key **private_key);

bool ue_x509_certificate_generate_self_signed_ca(char *C, char *CN, ue_x509_certificate **certificate, ue_private_key **private_key);

bool ue_x509_certificate_generate_signed(ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key,
    char *C, char *CN, ue_x509_certificate **certificate, ue_private_key **private_key);

bool ue_x509_certificate_print_pair(ue_x509_certificate *certificate, ue_private_key *private_key, char *certificate_file_name, char *private_key_file_name);

#endif
