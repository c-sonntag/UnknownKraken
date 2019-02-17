/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <uk/crypto/api/certificate/x509_csr.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>
#include <uk/crypto/impl/errorHandling/openssl_error_handling.h>

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <string.h>
#include <limits.h>

struct uk_crypto_x509_csr {
    X509_REQ *impl;
};

uk_crypto_x509_csr *uk_crypto_x509_csr_create(uk_crypto_x509_certificate *certificate, uk_crypto_private_key *private_key) {
    uk_crypto_x509_csr *csr;
    EVP_MD const *digest = EVP_sha256();

    csr = NULL;

    uk_utils_safe_alloc(csr, uk_crypto_x509_csr, 1);

    if ((csr->impl = X509_to_X509_REQ(uk_crypto_x509_certificate_get_impl(certificate), uk_crypto_private_key_get_impl(private_key), digest)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to convert X509 certificate to X509 csr");
        uk_utils_safe_free(csr);
        return NULL;
    }

    return csr;
}

void uk_crypto_x509_csr_destroy(uk_crypto_x509_csr *csr) {
    if (csr) {
        if (csr->impl) {
            X509_REQ_free(csr->impl);
        }
        uk_utils_safe_free(csr);
    }
}

bool uk_crypto_x509_csr_print(uk_crypto_x509_csr *csr, FILE *fd) {
    BIO *out_bio;

    if ((out_bio = BIO_new_fp(fd, BIO_NOCLOSE)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create BIO from specified fd");
        return false;
    }

    if (!PEM_write_bio_X509_REQ(out_bio, csr->impl)) {
        uk_utils_stacktrace_push_msg("Failed to write csr to BIO in PEM format");
        BIO_free_all(out_bio);
        return false;
    }

    BIO_free_all(out_bio);
    return true;
}

char *uk_crypto_x509_csr_to_string(uk_crypto_x509_csr *csr) {
    BIO *csr_bio;
    char *error_buffer, *buffer;
    int buffer_size;

    csr_bio = NULL;
    error_buffer = NULL;
    buffer = NULL;
    buffer_size = 0;

    if ((csr_bio = BIO_new(BIO_s_mem())) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "BIO_new for csr");
        goto clean_up;
    }

    if (!PEM_write_bio_X509_REQ(csr_bio, csr->impl)) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to write csr to BIO in PEM format");
        goto clean_up;
    }

    buffer_size = BIO_pending(csr_bio);

    uk_utils_safe_alloc(buffer, char, buffer_size + 1);

    if (BIO_read(csr_bio, buffer, buffer_size) < 0) {
        uk_crypto_openssl_error_handling(error_buffer, "BIO_read csr_bio");
        uk_utils_safe_free(buffer);
        buffer = NULL;
        goto clean_up;
    }

clean_up:
    BIO_free_all(csr_bio);
    uk_utils_safe_free(error_buffer);
    return buffer;
}

uk_crypto_x509_csr *uk_crypto_x509_string_to_csr(char *string) {
    uk_crypto_x509_csr *csr;
    BIO *bio;
    char *error_buffer;
    size_t string_size;

    uk_utils_check_parameter_or_return(string);

    csr = NULL;
    string_size = strlen(string);

    if (string_size > INT_MAX) {
        uk_utils_stacktrace_push_msg("BIO_new_mem_buf() take a length in int but string_size > INT_MAX");
        return NULL;
    }

    uk_utils_safe_alloc(csr, uk_crypto_x509_csr, 1)
    bio = NULL;
    error_buffer = NULL;

    if ((bio = BIO_new_mem_buf(string, (int)string_size)) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "BIO_new_mem_buf");
        uk_utils_safe_free(csr);
        goto clean_up;
    }

    if (!PEM_read_bio_X509_REQ(bio, &csr->impl, NULL, NULL)) {
        uk_crypto_openssl_error_handling(error_buffer, "PEM_read_bio_X509_REQ");
        uk_utils_safe_free(csr);
        goto clean_up;
    }

clean_up:
    uk_utils_safe_free(error_buffer);
    BIO_free_all(bio);
    return csr;
}

uk_crypto_x509_csr *uk_crypto_x509_bytes_to_csr(unsigned char *data, size_t data_size) {
    uk_crypto_x509_csr *csr;
    BIO *bio;
    char *error_buffer;

    if (data_size > INT_MAX) {
        uk_utils_stacktrace_push_msg("BIO_new_mem_buf() take length in int but data_size > INT_MAX");
        return NULL;
    }

    csr = NULL;
    uk_utils_safe_alloc(csr, uk_crypto_x509_csr, 1)
    bio = NULL;
    error_buffer = NULL;
    csr->impl = NULL;

    if ((bio = BIO_new_mem_buf(data, (int)data_size)) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "BIO_new_mem_buf");
        uk_utils_safe_free(csr);
        csr = NULL;
        goto clean_up;
    }

    if ((csr->impl = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL)) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "PEM_read_bio_X509_REQ");
        uk_utils_safe_free(csr);
        csr = NULL;
        goto clean_up;
    }

clean_up:
    uk_utils_safe_free(error_buffer);
    BIO_free_all(bio);
    return csr;
}

uk_crypto_x509_certificate *uk_crypto_x509_csr_sign(uk_crypto_x509_csr *csr, uk_crypto_private_key *private_key) {
    uk_crypto_x509_certificate *certificate;
    X509 *certificate_impl;

    if (!X509_REQ_sign(csr->impl, uk_crypto_private_key_get_impl(private_key), EVP_sha256())) {
        uk_utils_stacktrace_push_msg("Failed to sign CSR");
        return NULL;
    }

    certificate = uk_crypto_x509_certificate_create_empty();

    certificate_impl = X509_REQ_to_X509(csr->impl, 0, uk_crypto_private_key_get_impl(private_key));

    uk_crypto_x509_certificate_set_impl(certificate, certificate_impl);

    return certificate;
}

void *uk_crypto_x509_csr_get_impl(uk_crypto_x509_csr *csr) {
    return csr->impl;
}
