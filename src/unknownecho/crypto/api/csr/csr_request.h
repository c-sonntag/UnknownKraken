#ifndef UNKNOWNECHO_CSR_REQUEST_H
#define UNKNOWNECHO_CSR_REQUEST_H

#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/sym_key.h>

#include <stddef.h>

unsigned char *ue_csr_build_client_request(ue_x509_certificate *certificate, ue_private_key *private_key,
    ue_public_key *ca_public_key, size_t *cipher_data_size, ue_sym_key *future_key, unsigned char *iv, size_t iv_size);

ue_x509_certificate *ue_csr_process_server_response(unsigned char *server_response, size_t server_response_size, ue_sym_key *key,
    unsigned char *iv, size_t iv_size);

unsigned char *ue_csr_build_server_response(ue_private_key *csr_private_key, ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key,
    unsigned char *client_request, size_t client_request_size, size_t *server_response_size, ue_x509_certificate **signed_certificate);

#endif
