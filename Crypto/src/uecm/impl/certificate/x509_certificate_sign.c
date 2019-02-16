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

#include <uecm/api/certificate/x509_certificate_sign.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <uecm/utils/crypto_random.h>
#include <ei/ei.h>
#include <uecm/defines.h>

#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

static bool generate_set_random_serial(X509 *crt) {
    unsigned char serial_bytes[20];

    if (!uecm_crypto_random_bytes(serial_bytes, 20)) {
        ei_stacktrace_push_msg("Failed to gen crypto random bytes");
        return false;
    }

    serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
    BIGNUM *bn = BN_new();
    BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    BN_to_ASN1_INTEGER(bn, serial);

    X509_set_serialNumber(crt, serial); // Set serial.

    ASN1_INTEGER_free(serial);
    BN_free(bn);
    return true;
}

uecm_x509_certificate *uecm_x509_certificate_sign_from_csr(uecm_x509_csr *csr, uecm_x509_certificate *ca_certificate, uecm_private_key *ca_private_key) {
    X509 *certificate_impl;
    uecm_x509_certificate *certificate;
    EVP_PKEY *req_pubkey;
    char *error_buffer;

    ei_check_parameter_or_return(csr);
    ei_check_parameter_or_return(ca_certificate);
    ei_check_parameter_or_return(ca_private_key);

    certificate_impl = X509_new();
    certificate = uecm_x509_certificate_create_empty();
    req_pubkey = NULL;
    error_buffer = NULL;

    /* Set version to X509v3 */
    X509_set_version(certificate_impl, 2);

    /* Generate random 20 byte serial. */
    if (!generate_set_random_serial(certificate_impl)) {
        ei_stacktrace_push_msg("Failed to generate and set random serial to certificate impl");
        goto clean_up_failed;
    }

    /* Set issuer to CA's subject. */
    X509_set_issuer_name(certificate_impl, X509_get_subject_name(uecm_x509_certificate_get_impl(ca_certificate)));

    /* Set validity of certificate to 2 years. */
    X509_gmtime_adj(X509_get_notBefore(certificate_impl), 0);
    X509_gmtime_adj(X509_get_notAfter(certificate_impl), (long)UNKNOWNECHOCRYPTOMODULE_DEFAULT_X509_NOT_AFTER_YEAR *
        UNKNOWNECHOCRYPTOMODULE_DEFAULT_X509_NOT_AFTER_DAYS * 3600);

    if (!X509_set_subject_name(certificate_impl, X509_REQ_get_subject_name((X509_REQ *)uecm_x509_csr_get_impl(csr)))) {
        ei_stacktrace_push_msg("Failed to set subject name to certificate impl")
        goto clean_up_failed;
    }
    req_pubkey = X509_REQ_get_pubkey(uecm_x509_csr_get_impl(csr));
    if (!X509_set_pubkey(certificate_impl, req_pubkey)) {
        ei_stacktrace_push_msg("Failed to set req pubkey to certificate impl");
        goto clean_up_failed;
    }

    if (X509_sign(certificate_impl, uecm_private_key_get_impl(ca_private_key), EVP_get_digestbyname(UNKNOWNECHOCRYPTOMODULE_DEFAULT_DIGEST_NAME)) == 0) {
        uecm_openssl_error_handling(error_buffer, "X509_sign");
        goto clean_up_failed;
    }

    uecm_x509_certificate_set_impl(certificate, certificate_impl);
    EVP_PKEY_free(req_pubkey);

    return certificate;

clean_up_failed:
    uecm_x509_certificate_destroy(certificate);
    X509_free(certificate_impl);
    EVP_PKEY_free(req_pubkey);
    return NULL;
}

bool uecm_x509_certificate_verify(uecm_x509_certificate *signed_certificate, uecm_x509_certificate *ca_certificate) {
    bool result;
    X509_STORE_CTX *verify_ctx;
    X509_STORE *store;
    char *error_buffer;

    result = false;
    verify_ctx = NULL;
    store = NULL;
    error_buffer = NULL;

    ei_check_parameter_or_return(signed_certificate);
    ei_check_parameter_or_return(ca_certificate);

    if ((store = X509_STORE_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "X509_STORE_new");
        goto clean_up;
    }

    if ((verify_ctx = X509_STORE_CTX_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "X509_STORE_CTX_new");
        goto clean_up;
    }

    if (X509_STORE_add_cert(store, uecm_x509_certificate_get_impl(ca_certificate)) == 0) {
        uecm_openssl_error_handling(error_buffer, "X509_STORE_add_cert");
        goto clean_up;
    }

    if (X509_STORE_CTX_init(verify_ctx, store, uecm_x509_certificate_get_impl(signed_certificate), NULL) == 0) {
        uecm_openssl_error_handling(error_buffer, "X509_STORE_CTX_init");
        goto clean_up;
    }

    if (X509_verify_cert(verify_ctx) != 1) {
        ei_stacktrace_push_msg(X509_verify_cert_error_string(X509_STORE_CTX_get_error(verify_ctx)));
        goto clean_up;
    }

    result = true;

clean_up:
    if (verify_ctx) {
        X509_STORE_CTX_free(verify_ctx);
    }
    if (store) {
        X509_STORE_free(store);
    }
    ueum_safe_free(error_buffer);
    return result;
}
