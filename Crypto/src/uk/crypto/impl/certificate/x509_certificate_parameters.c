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

#include <uk/crypto/api/certificate/x509_certificate_parameters.h>
#include <uk/crypto/utils/crypto_random.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/defines.h>

struct uk_crypto_x509_certificate_parameters {
    unsigned char *serial;
    int serial_length;
    int bits;
    int days;
    char *C;
    char *CN;
    char *OU;
    char *O;
    char *basic_constraint;
    char *subject_key_identifier;
    char *cert_type;
    bool self_signed;
};

uk_crypto_x509_certificate_parameters *uk_crypto_x509_certificate_parameters_create() {
    uk_crypto_x509_certificate_parameters *parameters;

    parameters = NULL;

    uk_utils_safe_alloc(parameters, uk_crypto_x509_certificate_parameters, 1);
    uk_utils_safe_alloc(parameters->serial, unsigned char, UnknownKrakenCrypto_DEFUALT_X509_SERIAL_LENGTH);
    if (!uk_crypto_crypto_random_bytes(parameters->serial, UnknownKrakenCrypto_DEFUALT_X509_SERIAL_LENGTH)) {
        uk_utils_stacktrace_push_msg("Failed to gen crypto random bytes");
        return false;
    }
    /* @todo set default serial length in defines */
    parameters->serial_length = UnknownKrakenCrypto_DEFUALT_X509_SERIAL_LENGTH;
    /* Ensure serial is positive */
    parameters->serial[0] &= 0x7f;

    parameters->bits = UnknownKrakenCrypto_DEFAULT_RSA_KEY_BITS;
    parameters->days = UnknownKrakenCrypto_DEFAULT_X509_NOT_AFTER_DAYS;
    parameters->C = NULL;
    parameters->CN = NULL;
    parameters->basic_constraint = NULL;
    parameters->subject_key_identifier = NULL;
    parameters->cert_type = NULL;
    parameters->self_signed = false;

    return parameters;
}

void uk_crypto_x509_certificate_parameters_destroy(uk_crypto_x509_certificate_parameters *parameters) {
    if (parameters) {
        uk_utils_safe_free(parameters->C);
        uk_utils_safe_free(parameters->CN);
        uk_utils_safe_free(parameters->basic_constraint);
        uk_utils_safe_free(parameters->subject_key_identifier);
        uk_utils_safe_free(parameters->cert_type);
        uk_utils_safe_free(parameters->serial);
        uk_utils_safe_free(parameters);
    }
}

unsigned char *uk_crypto_x509_certificate_parameters_get_serial(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->serial;
}

int uk_crypto_x509_certificate_parameters_get_serial_length(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->serial_length;
}

bool uk_crypto_x509_certificate_parameters_set_bits(uk_crypto_x509_certificate_parameters *parameters, int bits) {
    parameters->bits = bits;
    return true;
}

int uk_crypto_x509_certificate_parameters_get_bits(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->bits;
}

bool uk_crypto_x509_certificate_parameters_set_days(uk_crypto_x509_certificate_parameters *parameters, int days) {
    parameters->days = days;
    return true;
}

int uk_crypto_x509_certificate_parameters_get_days(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->days;
}

bool uk_crypto_x509_certificate_parameters_set_country(uk_crypto_x509_certificate_parameters *parameters, char *country) {
    parameters->C = uk_utils_string_create_from(country);
    return true;
}

char *uk_crypto_x509_certificate_parameters_get_country(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->C;
}

bool uk_crypto_x509_certificate_parameters_set_common_name(uk_crypto_x509_certificate_parameters *parameters, char *common_name) {
    parameters->CN = uk_utils_string_create_from(common_name);
    return true;
}

char *uk_crypto_x509_certificate_parameters_get_common_name(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->CN;
}

bool uk_crypto_x509_certificate_parameters_set_organizational_unit(uk_crypto_x509_certificate_parameters *parameters, char *organizational_unit) {
    parameters->OU = uk_utils_string_create_from(organizational_unit);
    return true;
}

char *uk_crypto_x509_certificate_parameters_get_oranizational_unit(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->OU;
}

bool uk_crypto_x509_certificate_parameters_set_organization(uk_crypto_x509_certificate_parameters *parameters, char *organization) {
    parameters->O = uk_utils_string_create_from(organization);
    return true;
}

char *uk_crypto_x509_certificate_parameters_get_oranization(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->O;
}

bool uk_crypto_x509_certificate_parameters_set_ca_type(uk_crypto_x509_certificate_parameters *parameters) {
    parameters->basic_constraint = uk_utils_string_create_from("CA:TRUE");
    parameters->cert_type = uk_utils_string_create_from("sslCA");
    return true;
}

char *uk_crypto_x509_certificate_parameters_get_constraint(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->basic_constraint;
}

char *uk_crypto_x509_certificate_parameters_get_cert_type(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->cert_type;
}

bool uk_crypto_x509_certificate_parameters_set_subject_key_identifier_as_hash(uk_crypto_x509_certificate_parameters *parameters) {
    parameters->subject_key_identifier = uk_utils_string_create_from("hash");
    return true;
}

char *uk_crypto_x509_certificate_parameters_get_subject_key_identifier(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->subject_key_identifier;
}

bool uk_crypto_x509_certificate_parameters_set_self_signed(uk_crypto_x509_certificate_parameters *parameters) {
    parameters->self_signed = true;
    return true;
}

bool uk_crypto_x509_certificate_parameters_is_self_signed(uk_crypto_x509_certificate_parameters *parameters) {
    return parameters->self_signed;
}
