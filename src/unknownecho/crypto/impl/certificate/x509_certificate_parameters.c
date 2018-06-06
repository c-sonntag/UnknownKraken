/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/crypto/api/certificate/x509_certificate_parameters.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/alloc.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/defines.h>

struct ue_x509_certificate_parameters {
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

ue_x509_certificate_parameters *ue_x509_certificate_parameters_create() {
    ue_x509_certificate_parameters *parameters;

    ue_safe_alloc(parameters, ue_x509_certificate_parameters, 1);
    ue_safe_alloc(parameters->serial, unsigned char, UNKNOWNECHO_DEFUALT_X509_SERIAL_LENGTH);
	if (!ue_crypto_random_bytes(parameters->serial, UNKNOWNECHO_DEFUALT_X509_SERIAL_LENGTH)) {
		ei_stacktrace_push_msg("Failed to gen crypto random bytes");
		return false;
	}
    /* @todo set default serial length in defines */
    parameters->serial_length = UNKNOWNECHO_DEFUALT_X509_SERIAL_LENGTH;
    /* Ensure serial is positive */
	parameters->serial[0] &= 0x7f;

    parameters->bits = UNKNOWNECHO_DEFAULT_RSA_KEY_BITS;
    parameters->days = UNKNOWNECHO_DEFAULT_X509_NOT_AFTER_DAYS;
    parameters->C = NULL;
    parameters->CN = NULL;
    parameters->basic_constraint = NULL;
    parameters->subject_key_identifier = NULL;
    parameters->cert_type = NULL;
    parameters->self_signed = false;

    return parameters;
}

void ue_x509_certificate_parameters_destroy(ue_x509_certificate_parameters *parameters) {
    if (parameters) {
        ue_safe_free(parameters->C);
        ue_safe_free(parameters->CN);
        ue_safe_free(parameters->basic_constraint);
        ue_safe_free(parameters->subject_key_identifier);
        ue_safe_free(parameters->cert_type);
        ue_safe_free(parameters->serial);
        ue_safe_free(parameters);
    }
}

unsigned char *ue_x509_certificate_parameters_get_serial(ue_x509_certificate_parameters *parameters) {
    return parameters->serial;
}

int ue_x509_certificate_parameters_get_serial_length(ue_x509_certificate_parameters *parameters) {
    return parameters->serial_length;
}

bool ue_x509_certificate_parameters_set_bits(ue_x509_certificate_parameters *parameters, int bits) {
    parameters->bits = bits;
    return true;
}

int ue_x509_certificate_parameters_get_bits(ue_x509_certificate_parameters *parameters) {
    return parameters->bits;
}

bool ue_x509_certificate_parameters_set_days(ue_x509_certificate_parameters *parameters, int days) {
    parameters->days = days;
    return true;
}

int ue_x509_certificate_parameters_get_days(ue_x509_certificate_parameters *parameters) {
    return parameters->days;
}

bool ue_x509_certificate_parameters_set_country(ue_x509_certificate_parameters *parameters, char *country) {
    parameters->C = ue_string_create_from(country);
    return true;
}

char *ue_x509_certificate_parameters_get_country(ue_x509_certificate_parameters *parameters) {
    return parameters->C;
}

bool ue_x509_certificate_parameters_set_common_name(ue_x509_certificate_parameters *parameters, char *common_name) {
    parameters->CN = ue_string_create_from(common_name);
    return true;
}

char *ue_x509_certificate_parameters_get_common_name(ue_x509_certificate_parameters *parameters) {
    return parameters->CN;
}

bool ue_x509_certificate_parameters_set_organizational_unit(ue_x509_certificate_parameters *parameters, char *organizational_unit) {
    parameters->OU = ue_string_create_from(organizational_unit);
    return true;
}

char *ue_x509_certificate_parameters_get_oranizational_unit(ue_x509_certificate_parameters *parameters) {
    return parameters->OU;
}

bool ue_x509_certificate_parameters_set_organization(ue_x509_certificate_parameters *parameters, char *organization) {
    parameters->O = ue_string_create_from(organization);
    return true;
}

char *ue_x509_certificate_parameters_get_oranization(ue_x509_certificate_parameters *parameters) {
    return parameters->O;
}

bool ue_x509_certificate_parameters_set_ca_type(ue_x509_certificate_parameters *parameters) {
    parameters->basic_constraint = ue_string_create_from("CA:TRUE");
    parameters->cert_type = ue_string_create_from("sslCA");
    return true;
}

char *ue_x509_certificate_parameters_get_constraint(ue_x509_certificate_parameters *parameters) {
    return parameters->basic_constraint;
}

char *ue_x509_certificate_parameters_get_cert_type(ue_x509_certificate_parameters *parameters) {
    return parameters->cert_type;
}

bool ue_x509_certificate_parameters_set_subject_key_identifier_as_hash(ue_x509_certificate_parameters *parameters) {
    parameters->subject_key_identifier = ue_string_create_from("hash");
    return true;
}

char *ue_x509_certificate_parameters_get_subject_key_identifier(ue_x509_certificate_parameters *parameters) {
    return parameters->subject_key_identifier;
}

bool ue_x509_certificate_parameters_set_self_signed(ue_x509_certificate_parameters *parameters) {
    parameters->self_signed = true;
    return true;
}

bool ue_x509_certificate_parameters_is_self_signed(ue_x509_certificate_parameters *parameters) {
    return parameters->self_signed;
}
