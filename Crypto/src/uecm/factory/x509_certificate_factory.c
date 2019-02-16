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

#include <uecm/api/certificate/x509_certificate_parameters.h>
#include <uecm/api/certificate/x509_certificate_generation.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <uecm/impl/key/rsa_keypair_generation.h>
#include <uecm/utils/crypto_random.h>
#include <ei/ei.h>
#include <uecm/defines.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>

#include <string.h>
#include <limits.h>


static bool generate_signed_key_pair(X509 *ca_crt, EVP_PKEY *ca_key, char *CN, X509 **crt, EVP_PKEY **key);

static bool generate_key_csr(EVP_PKEY **key, char *CN, X509_REQ **req);

/* Generates a 20 byte random serial number and sets in certificate. */
static bool generate_set_random_serial(X509 *crt);


bool uecm_x509_certificate_generate_self_signed_ca(char *CN, uecm_x509_certificate **certificate, uecm_private_key **private_key) {
    bool result;
    uecm_x509_certificate_parameters *parameters;
    uecm_x509_certificate *certificate_impl;
    uecm_private_key *private_key_impl;

    result = false;
    parameters = NULL;
    certificate_impl = NULL;
    private_key_impl = NULL;

    ei_check_parameter_or_return(CN);

    if ((parameters = uecm_x509_certificate_parameters_create()) == NULL) {
        ei_stacktrace_push_msg("Failed to create x509 parameters structure");
        return false;
    }

    if (!uecm_x509_certificate_parameters_set_common_name(parameters, CN)) {
        ei_stacktrace_push_msg("Failed to set CN to x509 parameters");
        goto clean_up;
    }

    if (!uecm_x509_certificate_parameters_set_ca_type(parameters)) {
        ei_stacktrace_push_msg("Failed to set certificate as ca type");
        goto clean_up;
    }

    if (!uecm_x509_certificate_parameters_set_subject_key_identifier_as_hash(parameters)) {
        ei_stacktrace_push_msg("Failed to set certificate subject key identifier as hash");
        goto clean_up;
    }

    if (!uecm_x509_certificate_parameters_set_self_signed(parameters)) {
        ei_stacktrace_push_msg("Failed to set certificate as self signed");
        goto clean_up;
    }

    if (!uecm_x509_certificate_generate(parameters, &certificate_impl, &private_key_impl)) {
        ei_stacktrace_push_msg("Failed to generate certificate and relative private key");
        goto clean_up;
    }

    result = true;
    *certificate = certificate_impl;
    *private_key = private_key_impl;

clean_up:
    uecm_x509_certificate_parameters_destroy(parameters);
    return result;
}

bool uecm_x509_certificate_generate_signed(uecm_x509_certificate *ca_certificate, uecm_private_key *ca_private_key,
    char *CN, uecm_x509_certificate **certificate, uecm_private_key **private_key) {

    X509 *certificate_impl;
    EVP_PKEY *private_key_impl;
    RSA *rsa;
    char *error_buffer;

    ei_check_parameter_or_return(ca_certificate);
    ei_check_parameter_or_return(ca_private_key);
    ei_check_parameter_or_return(CN);

    certificate_impl = NULL;
    private_key_impl = NULL;
    rsa = NULL;
    *certificate = NULL;
    *private_key = NULL;

    if (!generate_signed_key_pair(uecm_x509_certificate_get_impl(ca_certificate), uecm_private_key_get_impl(ca_private_key), CN,
        &certificate_impl, &private_key_impl)) {
        ei_stacktrace_push_msg("Failed to generate signed key pair");
        goto clean_up_failed;
    }

    if ((*certificate = uecm_x509_certificate_create_empty()) == NULL) {
        ei_stacktrace_push_msg("Failed to generate new x509 certificate");
        goto clean_up_failed;
    }

    if (!uecm_x509_certificate_set_impl(*certificate, certificate_impl)) {
        ei_stacktrace_push_msg("Failed to cert impl to cert");
        goto clean_up_failed;
    }

    if ((rsa = EVP_PKEY_get1_RSA(private_key_impl)) == NULL) {
        uecm_openssl_error_handling(error_buffer, "Failed to get RSA from EVP_PKEY");
        goto clean_up_failed;
    }

    if((*private_key = uecm_private_key_create(RSA_PRIVATE_KEY, rsa, RSA_size(rsa))) == NULL) {
        ei_stacktrace_push_msg("Failed to create new private key from RSA impl");
        goto clean_up_failed;
    }

    EVP_PKEY_free(private_key_impl);

    return true;

clean_up_failed:
    uecm_x509_certificate_destroy(*certificate);
    X509_free(certificate_impl);
    EVP_PKEY_free(private_key_impl);
    RSA_free(rsa);
    return false;
}

static bool generate_signed_key_pair(X509 *ca_crt, EVP_PKEY *ca_key, char *CN, X509 **crt, EVP_PKEY **key) {
    X509_REQ *req;
    EVP_PKEY *req_pubkey;
    char *error_buffer;

    ei_check_parameter_or_return(ca_crt);
    ei_check_parameter_or_return(ca_key);
    ei_check_parameter_or_return(CN);

    req = NULL;
    req_pubkey = NULL;
    error_buffer = NULL;
    *crt = NULL;
    *key = NULL;

    if (!generate_key_csr(key, CN, &req)) {
        ei_stacktrace_push_msg("Fialed to generate CSR key");
        return false;
    }

    if ((*crt = X509_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "Failed to create new X509");
        goto clean_up_failed;
    }

    /* Set version to X509v3 */
    X509_set_version(*crt, 2);

    /* Generate random 20 byte serial. */
    if (!generate_set_random_serial(*crt)) {
        ei_stacktrace_push_msg("Failed to generate and set random serial to cert");
        goto clean_up_failed;
    }

    /* Set issuer to CA's subject. */
    if (!X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt))) {
        ei_stacktrace_push_msg("Failed to set CA's CN as cert issuer name")
        goto clean_up_failed;
    }

    /* @todo get default not after in defines */
    X509_gmtime_adj(X509_get_notBefore(*crt), 0);
    X509_gmtime_adj(X509_get_notAfter(*crt), (long)UNKNOWNECHOCRYPTOMODULE_DEFAULT_X509_NOT_AFTER_YEAR *
        UNKNOWNECHOCRYPTOMODULE_DEFAULT_X509_NOT_AFTER_DAYS * 3600);

    /* Get the request's subject */
    X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
    req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(*crt, req_pubkey);

    /* Now perform the actual signing with the CA. */
    if (X509_sign(*crt, ca_key, EVP_get_digestbyname(UNKNOWNECHOCRYPTOMODULE_DEFAULT_DIGEST_NAME)) == 0) {
        uecm_openssl_error_handling(error_buffer, "Failed to sign X509 certificate");
        goto clean_up_failed;
    }

    X509_REQ_free(req);
    EVP_PKEY_free(req_pubkey);
    return true;

clean_up_failed:
    EVP_PKEY_free(*key);
    X509_REQ_free(req);
    X509_free(*crt);
    EVP_PKEY_free(req_pubkey);
    return false;
}

static bool generate_key_csr(EVP_PKEY **key, char *CN, X509_REQ **req) {
    char *error_buffer;
    RSA *rsa;
    X509_NAME *name;
    size_t CN_size;

    ei_check_parameter_or_return(CN);

    error_buffer = NULL;
    rsa = NULL;
    CN_size = strlen(CN);

    if (CN_size > INT_MAX) {
        ei_stacktrace_push_msg("X509_NAME_add_entry_by_txt() need length in int but CN_size > INT_MAX");
        return false;
    }

    if ((*key = EVP_PKEY_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "EVP_PKEY_new");
        goto clean_up_failed;
    }

    if ((*req = X509_REQ_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "X509_REQ_new");
        goto clean_up_failed;
    }

    /* @todo get default bits length in defines */
    if ((rsa = uecm_rsa_keypair_gen(UNKNOWNECHOCRYPTOMODULE_DEFAULT_RSA_KEY_BITS)) == NULL) {
        ei_stacktrace_push_msg("Failed to gen RSA keypair");
        goto clean_up_failed;
    }

    if (!EVP_PKEY_assign_RSA(*key, rsa)) {
        uecm_openssl_error_handling(error_buffer, "EVP_PKEY_assign_RSA");
        goto clean_up_failed;
    }

    X509_REQ_set_pubkey(*req, *key);

    /* Set the DN of the request. */
    name = X509_REQ_get_subject_name(*req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)CN, (int)CN_size, -1, 0);

    /* Self-sign the request to prove that we posses the key. */
    if (!X509_REQ_sign(*req, *key, EVP_get_digestbyname(UNKNOWNECHOCRYPTOMODULE_DEFAULT_DIGEST_NAME))) {
        uecm_openssl_error_handling(error_buffer, "X509_REQ_sign");
        goto clean_up_failed;
    }

    return true;

clean_up_failed:
    EVP_PKEY_free(*key);
    X509_REQ_free(*req);
    return false;
}

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
