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

#include <uecm/api/certificate/x509_certificate_generation.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <uecm/impl/key/rsa_keypair_generation.h>
#include <uecm/utils/crypto_random.h>
#include <ei/ei.h>
#include <ueum/ueum.h>
#include <uecm/defines.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <stdio.h>
#include <string.h>


static bool add_ext(X509 *cert, int nid, char *value);

static bool set_serial_number(X509 *x, unsigned char *serial_bytes, int serial_bytes_length);


bool uecm_x509_certificate_generate(uecm_x509_certificate_parameters *parameters, uecm_x509_certificate **certificate, uecm_private_key **private_key) {
    X509 *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *name;
    char *error_buffer;

    ei_check_parameter_or_return(parameters);

    x = NULL;
    pk = NULL;
    rsa = NULL;
    name = NULL;
    error_buffer = NULL;

    if ((x = X509_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "Failed to create new X509 implementation");
        return false;
    }

    if ((rsa = uecm_rsa_keypair_gen(uecm_x509_certificate_parameters_get_bits(parameters))) == NULL) {
        uecm_openssl_error_handling(error_buffer, "Failed to create new RSA keypair");
        goto clean_up_failed;
    }

    if ((*private_key = uecm_private_key_create(RSA_PRIVATE_KEY, rsa, uecm_x509_certificate_parameters_get_bits(parameters))) == NULL) {
        ei_stacktrace_push_msg("Failed to create private key from generated RSA");
        RSA_free(rsa);
        goto clean_up_failed;
    }

    RSA_free(rsa);

    pk = uecm_private_key_get_impl(*private_key);

    if ((*certificate = uecm_x509_certificate_create_empty()) == NULL) {
        ei_stacktrace_push_msg("Failed to create new X509 certificate");
        goto clean_up_failed;
    }

    /* Set to version 3 */
    X509_set_version(x, 2);

    if (!set_serial_number(x, uecm_x509_certificate_parameters_get_serial(parameters), uecm_x509_certificate_parameters_get_serial_length(parameters))) {
        ei_stacktrace_push_msg("Failed to set serial number to cert impl");
        goto clean_up_failed;
    }

    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), (long)UNKNOWNECHOCRYPTOMODULE_DEFAULT_X509_NOT_AFTER_YEAR * uecm_x509_certificate_parameters_get_days(parameters) * 3600);
    X509_set_pubkey(x, pk);

    name = X509_get_subject_name(x);

     if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)uecm_x509_certificate_parameters_get_common_name(parameters),
         (int)strlen(uecm_x509_certificate_parameters_get_common_name(parameters)), -1, 0)) {

         uecm_openssl_error_handling(error_buffer, "Failed to add CN to certificate");
         goto clean_up_failed;
     }

    if (uecm_x509_certificate_parameters_get_country(parameters)) {
        if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)uecm_x509_certificate_parameters_get_country(parameters),
            (int)strlen(uecm_x509_certificate_parameters_get_country(parameters)), -1, 0)) {

            uecm_openssl_error_handling(error_buffer, "Failed to add C to certificate");
            goto clean_up_failed;
        }
    }

    /**
     * If it's self signed set the issuer name to be the same as the
      * subject.
     */
    if (uecm_x509_certificate_parameters_is_self_signed(parameters)) {
        if (!X509_set_issuer_name(x, name)) {
            uecm_openssl_error_handling(error_buffer, "Failed to set issuer name for self signed cert");
            goto clean_up_failed;
        }
    }

    if (uecm_x509_certificate_parameters_get_constraint(parameters)) {
        if (!add_ext(x, NID_basic_constraints, uecm_x509_certificate_parameters_get_constraint(parameters))) {
            ei_stacktrace_push_msg("Failed to add constraint ext to cert");
            goto clean_up_failed;
        }
    }

    if (!add_ext(x, NID_subject_key_identifier, uecm_x509_certificate_parameters_get_subject_key_identifier(parameters))) {
        ei_stacktrace_push_msg("Failed to add subject key identifier ext to cert");
        goto clean_up_failed;
    }

    if (!X509_sign(x, pk, EVP_get_digestbyname(UNKNOWNECHOCRYPTOMODULE_DEFAULT_DIGEST_NAME))) {
        uecm_openssl_error_handling(error_buffer, "Failed to sign cert");
        goto clean_up_failed;
    }

    uecm_x509_certificate_set_impl(*certificate, x);

    return true;

clean_up_failed:
    uecm_x509_certificate_destroy(*certificate);
    X509_free(x);
    return false;
}

bool uecm_x509_certificate_print_pair(uecm_x509_certificate *certificate, uecm_private_key *private_key, char *certificate_file_name,
    char *private_key_file_name, char *passphrase) {

    bool result;
    FILE *private_key_fd, *certificate_fd;

    ei_check_parameter_or_return(certificate);
    ei_check_parameter_or_return(private_key);
    ei_check_parameter_or_return(certificate_file_name);
    ei_check_parameter_or_return(private_key_file_name);

    result = false;
    private_key_fd = NULL;
    certificate_fd = NULL;

    if ((certificate_fd = fopen(certificate_file_name, "wb")) == NULL) {
        ei_stacktrace_push_errno();
        goto clean_up;
    }

    if ((private_key_fd = fopen(private_key_file_name, "wb")) == NULL) {
        ei_stacktrace_push_errno();
        goto clean_up;
    }

    if (!uecm_x509_certificate_print(certificate, certificate_fd)) {
        ei_stacktrace_push_msg("Failed to print certificate to '%s' file", certificate_file_name);
        goto clean_up;
    }

    if (!uecm_private_key_print(private_key, private_key_fd, passphrase)) {
        ei_stacktrace_push_msg("Failed to print private key to '%s' file", private_key_file_name);
        goto clean_up;
    }

    result = true;

clean_up:
    ueum_safe_fclose(certificate_fd);
    ueum_safe_fclose(private_key_fd);
    return result;
}

static bool add_ext(X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex;
    X509V3_CTX ctx;

    /**
     * This sets the 'context' of the extensions without
     * configuration database
     */
    X509V3_set_ctx_nodb(&ctx);

    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

    if ((ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value)) == NULL) {
        ei_stacktrace_push_msg("Ext returned is null")
        return false;
    }

    if (!X509_add_ext(cert, ex, -1)) {
        ei_stacktrace_push_msg("Failed to add ext to cert");
        X509_EXTENSION_free(ex);
        return false;
    }

    X509_EXTENSION_free(ex);

    return true;
}

static bool set_serial_number(X509 *x, unsigned char *serial_bytes, int serial_bytes_length) {
    bool result;
    BIGNUM *bn;
    ASN1_INTEGER *serial;
    char *error_buffer;

    ei_check_parameter_or_return(x);
    ei_check_parameter_or_return(serial_bytes);
    ei_check_parameter_or_return(serial_bytes_length > 0);

    result = false;
    bn = BN_new();
    serial = ASN1_INTEGER_new();
    error_buffer = NULL;

    BN_bin2bn(serial_bytes, serial_bytes_length, bn);
    BN_to_ASN1_INTEGER(bn, serial);
    if (!X509_set_serialNumber(x, serial)) {
        uecm_openssl_error_handling(error_buffer, "X509_set_serialNumber");
        goto clean_up;
    }

    result = true;

clean_up:
    ASN1_INTEGER_free(serial);
    BN_free(bn);
    return result;
}
