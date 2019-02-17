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

#include <uk/crypto/api/certificate/x509_certificate.h>
#include <uk/crypto/impl/errorHandling/openssl_error_handling.h>
#include <uk/utils/ueum.h>

#include <uk/utils/ei.h>

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>


struct uk_crypto_x509_certificate {
    X509 *impl;
};


static bool load_certificate_pair(const char *cert_file_name, const char *private_key_file_name, const char *password, X509 **certificate, EVP_PKEY **private_key);


uk_crypto_x509_certificate *uk_crypto_x509_certificate_create_empty() {
    uk_crypto_x509_certificate *certificate;

    certificate = NULL;

    uk_utils_safe_alloc(certificate, uk_crypto_x509_certificate, 1);
    certificate->impl = NULL;

    return certificate;
}

bool uk_crypto_x509_certificate_load_from_file(const char *file_name, uk_crypto_x509_certificate **certificate) {
    bool result;
    X509 *certificate_impl;
    BIO *bio;
    char *error_buffer;

    uk_utils_check_parameter_or_return(file_name);

    result = false;
    certificate_impl = NULL;
    bio = NULL;
    error_buffer = NULL;

    bio = BIO_new(BIO_s_file());
    if (!BIO_read_filename(bio, file_name)) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to read file");
        goto clean_up;
    }

    if ((certificate_impl = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to read bio as PEM");
        goto clean_up;
    }

    if ((*certificate = uk_crypto_x509_certificate_create_empty()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create empty x509 certificate");
        X509_free(certificate_impl);
        goto clean_up;
    }
    if (!uk_crypto_x509_certificate_set_impl(*certificate, certificate_impl)) {
        uk_utils_stacktrace_push_msg("Failed to set x509 certificate impl to new uk_crypto_x509_certificate");
        uk_crypto_x509_certificate_destroy(*certificate);
        X509_free(certificate_impl);
        goto clean_up;
    }

    result = true;

clean_up:
    BIO_free_all(bio);
    return result;
}

bool uk_crypto_x509_certificate_load_from_files(const char *cert_file_name, const char *private_key_file_name, const char *password,
    uk_crypto_x509_certificate **certificate, uk_crypto_private_key **private_key) {

    X509 *certificate_impl;
    EVP_PKEY *private_key_impl;
    RSA *rsa;
    char *error_buffer;

    uk_utils_check_parameter_or_return(cert_file_name);
    uk_utils_check_parameter_or_return(private_key_file_name);

    certificate_impl = NULL;
    private_key_impl = NULL;
    rsa = NULL;
    error_buffer = NULL;

    if (!load_certificate_pair(cert_file_name, private_key_file_name, password, &certificate_impl, &private_key_impl)) {
        uk_utils_stacktrace_push_msg("Failed to load impl certificate pair files");
        return false;
    }

    if ((*certificate = uk_crypto_x509_certificate_create_empty()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create empty x509 certificate");
        goto clean_up_failed;
    }
    if (!uk_crypto_x509_certificate_set_impl(*certificate, certificate_impl)) {
        uk_utils_stacktrace_push_msg("Failed to set x509 certificate impl to new uk_crypto_x509_certificate");
        goto clean_up_failed;
    }

    if ((rsa = EVP_PKEY_get1_RSA(private_key_impl)) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to get RSA implementation from private key impl");
        goto clean_up_failed;
    }

    if ((*private_key = uk_crypto_private_key_create(RSA_PRIVATE_KEY, rsa, RSA_size(rsa))) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create uk_crypto_private_key from rsa impl");
        goto clean_up_failed;
    }

    EVP_PKEY_free(private_key_impl);
    return true;

clean_up_failed:
    X509_free(certificate_impl);
    EVP_PKEY_free(private_key_impl);
    uk_crypto_x509_certificate_destroy(*certificate);
    uk_crypto_private_key_destroy(*private_key);
    return false;
}

uk_crypto_x509_certificate *uk_crypto_x509_certificate_load_from_bytes(unsigned char *data, size_t data_size) {
    uk_crypto_x509_certificate *certificate;
    BIO *bio;
    char *error_buffer;
    X509 *certificate_impl;

    uk_utils_check_parameter_or_return(data);
    uk_utils_check_parameter_or_return(data_size > 0);

    if (data_size > INT_MAX) {
        uk_utils_stacktrace_push_msg("BIO_new_mem_buf() need a length in int, however data_size > INT_MAX");
        return NULL;
    }

    certificate = uk_crypto_x509_certificate_create_empty();
    bio = NULL;
    error_buffer = NULL;
    
    /* It's safe to cast data_size to int as we compare it with INT_MAX */
    if ((bio = BIO_new_mem_buf(data, (int)data_size)) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "BIO_new_mem_buf");
        uk_crypto_x509_certificate_destroy(certificate);
        goto clean_up;
    }

    if ((certificate_impl = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "PEM_read_bio_X509");
        uk_crypto_x509_certificate_destroy(certificate);
        certificate = NULL;
        goto clean_up;
    }

    uk_crypto_x509_certificate_set_impl(certificate, certificate_impl);

clean_up:
    BIO_free_all(bio);
    return certificate;
}

void uk_crypto_x509_certificate_destroy(uk_crypto_x509_certificate *certificate) {
    if (certificate) {
        if (certificate->impl) {
            X509_free(certificate->impl);
        }
        uk_utils_safe_free(certificate);
    }
}

void *uk_crypto_x509_certificate_get_impl(uk_crypto_x509_certificate *certificate) {
    if (!certificate) {
        uk_utils_stacktrace_push_msg("Specified certificate ptr is null");
        return NULL;
    }

    if (!certificate->impl) {
        uk_utils_stacktrace_push_msg("Specified certificate have no implementation");
        return NULL;
    }

    return certificate->impl;
}

bool uk_crypto_x509_certificate_set_impl(uk_crypto_x509_certificate *certificate, void *impl) {
    uk_utils_check_parameter_or_return(certificate);
    uk_utils_check_parameter_or_return(impl);

    certificate->impl = impl;
    return true;
}

bool uk_crypto_x509_certificate_equals(uk_crypto_x509_certificate *c1, uk_crypto_x509_certificate *c2) {
    return c1 && c2 && X509_cmp(c1->impl, c2->impl) == 0;
}

/* Since I only experimented the applink error in Windows */
#if (defined(_WIN32) || defined(_WIN64)) && False

#include <openssl/applink.c>

#endif

bool uk_crypto_x509_certificate_print(uk_crypto_x509_certificate *certificate, FILE *out_fd) {
    char *error_buffer;

    uk_utils_check_parameter_or_return(certificate);
    uk_utils_check_parameter_or_return(out_fd);

    error_buffer = NULL;

    if (PEM_write_X509(out_fd, certificate->impl) == 0) {
        uk_crypto_openssl_error_handling(error_buffer, "PEM_write_PrivateKey");
        return false;
    }

    return true;
}

char *uk_crypto_x509_certificate_to_pem_string(uk_crypto_x509_certificate *certificate, size_t *result_size) {
    BIO *bio;
    char *pem, *error_buffer;
    int size, result;

    uk_utils_check_parameter_or_return(certificate);

    bio = NULL;
    pem = NULL;
    error_buffer = NULL;
    *result_size = 0;

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to alloc new BIO");
        return NULL;
    }

    if (!PEM_write_bio_X509(bio, uk_crypto_x509_certificate_get_impl(certificate))) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to write x509 certificate as PEM");
        BIO_free_all(bio);
        return NULL;
    }

    if ((size = BIO_pending(bio)) <= 0) {
        uk_utils_stacktrace_push_msg("Bio have an invalid size");
        BIO_free_all(bio);
        return NULL;
    }

    uk_utils_safe_alloc(pem, char, size);

    result = BIO_read(bio, pem, size);
    if (result <= 0) {
        BIO_free_all(bio);
        uk_utils_safe_free(pem);
        if (result == 0) {
            uk_utils_stacktrace_push_msg("No data read because bio is empty");
        } else if (result == -1) {
            uk_utils_stacktrace_push_msg("Reading of bio data failed with an error");
        } else if (result == -2) {
            uk_utils_stacktrace_push_msg("This operation is not supported by this bio");
        }
        return NULL;
    }

    BIO_free_all(bio);

    *result_size = (int)size;

    return pem;
}

static int pass_cb(char *buf, int size, int rwflag, void *u) {
    size_t u_size;

    (void)size;
    (void)rwflag;

     memcpy(buf, (char *)u, strlen((char *)u));

     u_size = strlen(u);
     if (u_size > INT_MAX) {
         uk_utils_stacktrace_push_msg("pass_cb have to return int, but u_size > INT_MAX");
         return -1;
     }

     return (int)u_size;
 }

static bool load_certificate_pair(const char *cert_file_name, const char *private_key_file_name, const char *password,
    X509 **certificate, EVP_PKEY **private_key) {

    BIO *bio;
    char *error_buffer;

    uk_utils_check_parameter_or_return(cert_file_name);
    uk_utils_check_parameter_or_return(private_key_file_name);

    bio = NULL;
    error_buffer = NULL;
    *certificate = NULL;
    *private_key = NULL;

    /* Load certificate */
    if ((bio = BIO_new(BIO_s_file())) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to create new BIO for certificate");
        return false;
    }

    if (!BIO_read_filename(bio, cert_file_name)) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to read certificate file");
        goto clean_up;
    }

    if ((*certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to read BIO as PEM x509 certificate");
        goto clean_up;
    }

    BIO_free_all(bio);

    /* Load private key */
    if ((bio = BIO_new(BIO_s_file())) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to create new BIO for private key");
        goto clean_up;
    }

    if (!BIO_read_filename(bio, private_key_file_name)) {
        uk_crypto_openssl_error_handling(error_buffer, "Failed to read private key file");
        goto clean_up;
    }

    if (password) {
        /* @todo fix memory leak here when server user exit with ctrl+c */
        if ((*private_key = PEM_read_bio_PrivateKey(bio, NULL, pass_cb, (void *)password)) == NULL) {
            uk_crypto_openssl_error_handling(error_buffer, "Failed to read BIO as PEM private key with a password");
            goto clean_up;
        }
    } else {
        if ((*private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == NULL) {
            uk_crypto_openssl_error_handling(error_buffer, "Failed to read BIO as PEM private key without a password");
            goto clean_up;
        }
    }

    BIO_free_all(bio);

    return true;

clean_up:
    BIO_free_all(bio);
    X509_free(*certificate);
    EVP_PKEY_free(*private_key);
    return false;
}
