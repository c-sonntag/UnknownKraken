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

#include <uecm/api/certificate/x509_csr.h>
#include <ueum/ueum.h>
#include <ei/ei.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <string.h>
#include <limits.h>

struct uecm_x509_csr {
    X509_REQ *impl;
};

uecm_x509_csr *uecm_x509_csr_create(uecm_x509_certificate *certificate, uecm_private_key *private_key) {
    uecm_x509_csr *csr;
    EVP_MD const *digest = EVP_sha256();

    csr = NULL;

    ueum_safe_alloc(csr, uecm_x509_csr, 1);

    if ((csr->impl = X509_to_X509_REQ(uecm_x509_certificate_get_impl(certificate), uecm_private_key_get_impl(private_key), digest)) == NULL) {
        ei_stacktrace_push_msg("Failed to convert X509 certificate to X509 csr");
        ueum_safe_free(csr);
        return NULL;
    }

    return csr;
}

void uecm_x509_csr_destroy(uecm_x509_csr *csr) {
    if (csr) {
        if (csr->impl) {
            X509_REQ_free(csr->impl);
        }
        ueum_safe_free(csr);
    }
}

bool uecm_x509_csr_print(uecm_x509_csr *csr, FILE *fd) {
    BIO *out_bio;

    if ((out_bio = BIO_new_fp(fd, BIO_NOCLOSE)) == NULL) {
        ei_stacktrace_push_msg("Failed to create BIO from specified fd");
        return false;
    }

    if (!PEM_write_bio_X509_REQ(out_bio, csr->impl)) {
        ei_stacktrace_push_msg("Failed to write csr to BIO in PEM format");
        BIO_free_all(out_bio);
        return false;
    }

    BIO_free_all(out_bio);
    return true;
}

char *uecm_x509_csr_to_string(uecm_x509_csr *csr) {
    BIO *csr_bio;
    char *error_buffer, *buffer;
    int buffer_size;

    csr_bio = NULL;
    error_buffer = NULL;
    buffer = NULL;
    buffer_size = 0;

    if ((csr_bio = BIO_new(BIO_s_mem())) == NULL) {
        uecm_openssl_error_handling(error_buffer, "BIO_new for csr");
        goto clean_up;
    }

    if (!PEM_write_bio_X509_REQ(csr_bio, csr->impl)) {
        uecm_openssl_error_handling(error_buffer, "Failed to write csr to BIO in PEM format");
        goto clean_up;
    }

    buffer_size = BIO_pending(csr_bio);

    ueum_safe_alloc(buffer, char, buffer_size + 1);

    if (BIO_read(csr_bio, buffer, buffer_size) < 0) {
        uecm_openssl_error_handling(error_buffer, "BIO_read csr_bio");
        ueum_safe_free(buffer);
        buffer = NULL;
        goto clean_up;
    }

clean_up:
    BIO_free_all(csr_bio);
    ueum_safe_free(error_buffer);
    return buffer;
}

uecm_x509_csr *uecm_x509_string_to_csr(char *string) {
    uecm_x509_csr *csr;
    BIO *bio;
    char *error_buffer;
    size_t string_size;

    ei_check_parameter_or_return(string);

    csr = NULL;
    string_size = strlen(string);

    if (string_size > INT_MAX) {
        ei_stacktrace_push_msg("BIO_new_mem_buf() take a length in int but string_size > INT_MAX");
        return NULL;
    }

    ueum_safe_alloc(csr, uecm_x509_csr, 1)
    bio = NULL;
    error_buffer = NULL;

    if ((bio = BIO_new_mem_buf(string, (int)string_size)) == NULL) {
        uecm_openssl_error_handling(error_buffer, "BIO_new_mem_buf");
        ueum_safe_free(csr);
        goto clean_up;
    }

    if (!PEM_read_bio_X509_REQ(bio, &csr->impl, NULL, NULL)) {
        uecm_openssl_error_handling(error_buffer, "PEM_read_bio_X509_REQ");
        ueum_safe_free(csr);
        goto clean_up;
    }

clean_up:
    ueum_safe_free(error_buffer);
    BIO_free_all(bio);
    return csr;
}

uecm_x509_csr *uecm_x509_bytes_to_csr(unsigned char *data, size_t data_size) {
    uecm_x509_csr *csr;
    BIO *bio;
    char *error_buffer;

    if (data_size > INT_MAX) {
        ei_stacktrace_push_msg("BIO_new_mem_buf() take length in int but data_size > INT_MAX");
        return NULL;
    }

    csr = NULL;
    ueum_safe_alloc(csr, uecm_x509_csr, 1)
    bio = NULL;
    error_buffer = NULL;
    csr->impl = NULL;

    if ((bio = BIO_new_mem_buf(data, (int)data_size)) == NULL) {
        uecm_openssl_error_handling(error_buffer, "BIO_new_mem_buf");
        ueum_safe_free(csr);
        csr = NULL;
        goto clean_up;
    }

    if ((csr->impl = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL)) == NULL) {
        uecm_openssl_error_handling(error_buffer, "PEM_read_bio_X509_REQ");
        ueum_safe_free(csr);
        csr = NULL;
        goto clean_up;
    }

clean_up:
    ueum_safe_free(error_buffer);
    BIO_free_all(bio);
    return csr;
}

uecm_x509_certificate *uecm_x509_csr_sign(uecm_x509_csr *csr, uecm_private_key *private_key) {
    uecm_x509_certificate *certificate;
    X509 *certificate_impl;

    if (!X509_REQ_sign(csr->impl, uecm_private_key_get_impl(private_key), EVP_sha256())) {
        ei_stacktrace_push_msg("Failed to sign CSR");
        return NULL;
    }

    certificate = uecm_x509_certificate_create_empty();

    certificate_impl = X509_REQ_to_X509(csr->impl, 0, uecm_private_key_get_impl(private_key));

    uecm_x509_certificate_set_impl(certificate, certificate_impl);

    return certificate;
}

void *uecm_x509_csr_get_impl(uecm_x509_csr *csr) {
    return csr->impl;
}
