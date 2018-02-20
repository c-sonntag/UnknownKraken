#ifndef UNKNOWNECHO_X509_CERTIFICATE_SIGN_H
#define UNKNOWNECHO_X509_CERTIFICATE_SIGN_H

#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/certificate/x509_csr.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

ue_x509_certificate *ue_x509_certificate_sign_from_csr(ue_x509_csr *csr, ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key);

bool ue_x509_certificate_verify(ue_x509_certificate *signed_certificate, ue_x509_certificate *ca_certificate);

#endif
