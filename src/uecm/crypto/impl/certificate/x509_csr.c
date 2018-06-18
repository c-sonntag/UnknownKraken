/******************************************************************************************
 * Copyright (C) 2018 by Charly Lamothe													  *
 *																						  *
 * This file is part of LibUnknownEchoCryptoModule.										  *
 *																						  *
 *   LibUnknownEchoCryptoModule is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU General Public License as published by				  *
 *   the Free Software Foundation, either version 3 of the License, or					  *
 *   (at your option) any later version.												  *
 *																						  *
 *   LibUnknownEchoCryptoModule is distributed in the hope that it will be useful,        *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of						  *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  *
 *   GNU General Public License for more details.										  *
 *																						  *
 *   You should have received a copy of the GNU General Public License					  *
 *   along with LibUnknownEchoCryptoModule.  If not, see <http://www.gnu.org/licenses/>.  *
 ******************************************************************************************/

#include <uecm/crypto/api/certificate/x509_csr.h>
#include <uecm/alloc.h>
#include <ei/ei.h>
#include <uecm/crypto/impl/errorHandling/openssl_error_handling.h>

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <string.h>

struct uecm_x509_csr {
    X509_REQ *impl;
};

uecm_x509_csr *uecm_x509_csr_create(uecm_x509_certificate *certificate, uecm_private_key *private_key) {
    uecm_x509_csr *csr;
    EVP_MD const *digest = EVP_sha256();

    csr = NULL;

    uecm_safe_alloc(csr, uecm_x509_csr, 1);

    if (!(csr->impl = X509_to_X509_REQ(uecm_x509_certificate_get_impl(certificate), uecm_private_key_get_impl(private_key), digest))) {
        ei_stacktrace_push_msg("Failed to convert X509 certificate to X509 csr");
        uecm_safe_free(csr);
        return NULL;
    }

    return csr;
}

void uecm_x509_csr_destroy(uecm_x509_csr *csr) {
    if (csr) {
        if (csr->impl) {
            X509_REQ_free(csr->impl);
        }
        uecm_safe_free(csr);
    }
}

bool uecm_x509_csr_print(uecm_x509_csr *csr, FILE *fd) {
    BIO *out_bio;

    if (!(out_bio = BIO_new_fp(fd, BIO_NOCLOSE))) {
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
    size_t buffer_size;

    csr_bio = NULL;
    error_buffer = NULL;
    buffer = NULL;
    buffer_size = 0;

    if (!(csr_bio = BIO_new(BIO_s_mem()))) {
        uecm_openssl_error_handling(error_buffer, "BIO_new for csr");
        goto clean_up;
    }

    if (!PEM_write_bio_X509_REQ(csr_bio, csr->impl)) {
        uecm_openssl_error_handling(error_buffer, "Failed to write csr to BIO in PEM format");
        goto clean_up;
    }

    buffer_size = BIO_pending(csr_bio);

    uecm_safe_alloc(buffer, char, buffer_size + 1);

    if (BIO_read(csr_bio, buffer, buffer_size) < 0) {
        uecm_openssl_error_handling(error_buffer, "BIO_read csr_bio");
        uecm_safe_free(buffer);
        buffer = NULL;
        goto clean_up;
    }

clean_up:
    BIO_free_all(csr_bio);
    uecm_safe_free(error_buffer);
    return buffer;
}

uecm_x509_csr *uecm_x509_string_to_csr(char *string) {
    uecm_x509_csr *csr;
    BIO *bio;
    char *error_buffer;

    uecm_safe_alloc(csr, uecm_x509_csr, 1)
    bio = NULL;
    error_buffer = NULL;

    if (!(bio = BIO_new_mem_buf(string, strlen(string)))) {
		uecm_openssl_error_handling(error_buffer, "BIO_new_mem_buf");
        uecm_safe_free(csr);
		goto clean_up;
	}

    if (!PEM_read_bio_X509_REQ(bio, &csr->impl, NULL, NULL)) {
        uecm_openssl_error_handling(error_buffer, "PEM_read_bio_X509_REQ");
        uecm_safe_free(csr);
        goto clean_up;
    }

clean_up:
    uecm_safe_free(error_buffer);
    BIO_free_all(bio);
    return csr;
}

uecm_x509_csr *uecm_x509_bytes_to_csr(unsigned char *data, size_t data_size) {
    uecm_x509_csr *csr;
    BIO *bio;
    char *error_buffer;

    uecm_safe_alloc(csr, uecm_x509_csr, 1)
    bio = NULL;
    error_buffer = NULL;
    csr->impl = NULL;

    if (!(bio = BIO_new_mem_buf(data, data_size))) {
		uecm_openssl_error_handling(error_buffer, "BIO_new_mem_buf");
        uecm_safe_free(csr);
        csr = NULL;
		goto clean_up;
	}

    if (!(csr->impl = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL))) {
        uecm_openssl_error_handling(error_buffer, "PEM_read_bio_X509_REQ");
        uecm_safe_free(csr);
        csr = NULL;
        goto clean_up;
    }

clean_up:
    uecm_safe_free(error_buffer);
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
