#ifndef UNKNOWNECHO_X509_CSR_H
#define UNKNOWNECHO_X509_CSR_H

#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

#include <stdio.h>
#include <stddef.h>

typedef struct ue_x509_csr ue_x509_csr;

ue_x509_csr *ue_x509_csr_create(ue_x509_certificate *certificate, ue_private_key *private_key);

void ue_x509_csr_destroy(ue_x509_csr *csr);

bool ue_x509_csr_print(ue_x509_csr *csr, FILE *fd);

char *ue_x509_csr_to_string(ue_x509_csr *csr);

ue_x509_csr *ue_x509_string_to_csr(char *string);

ue_x509_csr *ue_x509_bytes_to_csr(unsigned char *data, size_t data_size);

ue_x509_certificate *ue_x509_csr_sign(ue_x509_csr *csr, ue_private_key *private_key);

void *ue_x509_csr_get_impl(ue_x509_csr *csr);

#endif
