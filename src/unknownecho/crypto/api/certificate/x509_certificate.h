#ifndef UNKNOWNECHO_X509_CERTIFICATE_H
#define UNKNOWNECHO_X509_CERTIFICATE_H

#include <unknownecho/bool.h>
#include <unknownecho/crypto/api/key/private_key.h>

#include <stdio.h>
#include <stddef.h>

typedef struct ue_x509_certificate ue_x509_certificate;

ue_x509_certificate *ue_x509_certificate_create_empty();

bool ue_x509_certificate_load_from_file(const char *file_name, ue_x509_certificate **certificate);

bool ue_x509_certificate_load_from_files(const char *cert_file_name, const char *key_file_name, ue_x509_certificate **certificate, ue_private_key **private_key);

ue_x509_certificate *ue_x509_certificate_load_from_bytes(unsigned char *data, size_t data_size);

void ue_x509_certificate_destroy(ue_x509_certificate *certificate);

void *ue_x509_certificate_get_impl(ue_x509_certificate *certificate);

bool ue_x509_certificate_set_impl(ue_x509_certificate *certificate, void *impl);

bool ue_x509_certificate_equals(ue_x509_certificate *c1, ue_x509_certificate *c2);

bool ue_x509_certificate_print(ue_x509_certificate *certificate, FILE *out_fd);

char *ue_x509_certificate_to_pem_string(ue_x509_certificate *certificate);

#endif
