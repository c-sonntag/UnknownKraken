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

#include <uk/crypto/factory/pkcs12_keystore_factory.h>
#include <uk/crypto/factory/x509_certificate_factory.h>
#include <uk/crypto/api/key/private_key.h>
#include <uk/crypto/api/certificate/x509_certificate.h>
#include <uk/crypto/api/certificate/x509_certificate_generation.h>
#include <uk/crypto/api/certificate/x509_certificate_parameters.h>
#include <uk/utils/ei.h>

static bool generate_certificate(char *CN, uk_crypto_x509_certificate **certificate, uk_crypto_private_key **private_key) {
    bool result;
    uk_crypto_x509_certificate_parameters *parameters;

    result = false;
    parameters = NULL;

    if ((parameters = uk_crypto_x509_certificate_parameters_create()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create x509 parameters structure");
        return false;
    }

    // @TODO add client id ?
    if (!uk_crypto_x509_certificate_parameters_set_common_name(parameters, CN)) {
        uk_utils_stacktrace_push_msg("Failed to set CN to x509 parameters");
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_parameters_set_ca_type(parameters)) {
        uk_utils_stacktrace_push_msg("Failed to set certificate as ca type");
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_parameters_set_subject_key_identifier_as_hash(parameters)) {
        uk_utils_stacktrace_push_msg("Failed to set certificate subject key identifier as hash");
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_parameters_set_self_signed(parameters)) {
        uk_utils_stacktrace_push_msg("Failed to set certificate as self signed");
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_generate(parameters, certificate, private_key)) {
        uk_utils_stacktrace_push_msg("Failed to generate certificate and relative private key");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_crypto_x509_certificate_parameters_destroy(parameters);
    return result;
}

uk_crypto_pkcs12_keystore *uk_crypto_pkcs12_keystore_create_random(char *CN, char *friendly_name) {
    uk_crypto_x509_certificate *certificate;
    uk_crypto_private_key *private_key;
    uk_crypto_pkcs12_keystore *keystore;

    if (!generate_certificate(CN, &certificate, &private_key)) {
        uk_utils_stacktrace_push_msg("Failed to generate random certificate and private key");
        return NULL;
    }

    if ((keystore = uk_crypto_pkcs12_keystore_create(certificate, private_key, friendly_name)) == NULL) {
        uk_crypto_x509_certificate_destroy(certificate);
        uk_crypto_private_key_destroy(private_key);
        uk_utils_stacktrace_push_msg("Failed to create keystore from random certificate and private key");
        return NULL;
    }

    return keystore;
}

uk_crypto_pkcs12_keystore *uk_crypto_pkcs12_keystore_create_from_files(char *certificate_path, char *private_key_path, const char *private_key_password, char *friendly_name) {
    uk_crypto_x509_certificate *certificate;
    uk_crypto_private_key *private_key;
    uk_crypto_pkcs12_keystore *keystore;

    if (!uk_crypto_x509_certificate_load_from_files(certificate_path, private_key_path, private_key_password, &certificate, &private_key)) {
        uk_utils_stacktrace_push_msg("Failed to load certificate and private key from '%s' and '%s' files", certificate_path, private_key_path);
        return NULL;
    }

    if ((keystore = uk_crypto_pkcs12_keystore_create(certificate, private_key, friendly_name)) == NULL) {
        uk_crypto_x509_certificate_destroy(certificate);
        uk_crypto_private_key_destroy(private_key);
        uk_utils_stacktrace_push_msg("Failed to create keystore from '%s' and '%s' files", certificate_path, private_key_path);
        return NULL;
    }

    return keystore;
}
