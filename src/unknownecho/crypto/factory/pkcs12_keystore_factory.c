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

#include <unknownecho/crypto/factory/pkcs12_keystore_factory.h>
#include <unknownecho/crypto/factory/x509_certificate_factory.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_generation.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_parameters.h>
#include <ei/ei.h>

static bool generate_certificate(char *CN, ue_x509_certificate **certificate, ue_private_key **private_key) {
    bool result;
    ue_x509_certificate_parameters *parameters;

	result = false;
	parameters = NULL;

	if (!(parameters = ue_x509_certificate_parameters_create())) {
		ei_stacktrace_push_msg("Failed to create x509 parameters structure");
		return false;
	}

    // @TODO add client id ?
    if (!ue_x509_certificate_parameters_set_common_name(parameters, CN)) {
		ei_stacktrace_push_msg("Failed to set CN to x509 parameters");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_ca_type(parameters)) {
		ei_stacktrace_push_msg("Failed to set certificate as ca type");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_subject_key_identifier_as_hash(parameters)) {
		ei_stacktrace_push_msg("Failed to set certificate subject key identifier as hash");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_self_signed(parameters)) {
		ei_stacktrace_push_msg("Failed to set certificate as self signed");
		goto clean_up;
	}

    if (!ue_x509_certificate_generate(parameters, certificate, private_key)) {
		ei_stacktrace_push_msg("Failed to generate certificate and relative private key");
		goto clean_up;
	}

    result = true;

clean_up:
    ue_x509_certificate_parameters_destroy(parameters);
    return result;
}

ue_pkcs12_keystore *ue_pkcs12_keystore_create_random(char *CN, char *friendly_name) {
    ue_x509_certificate *certificate;
    ue_private_key *private_key;
    ue_pkcs12_keystore *keystore;

    if (!generate_certificate(CN, &certificate, &private_key)) {
        ei_stacktrace_push_msg("Failed to generate random certificate and private key");
        return NULL;
    }

    if (!(keystore = ue_pkcs12_keystore_create(certificate, private_key, friendly_name))) {
        ue_x509_certificate_destroy(certificate);
        ue_private_key_destroy(private_key);
        ei_stacktrace_push_msg("Failed to create keystore from random certificate and private key");
        return NULL;
    }

    return keystore;
}

ue_pkcs12_keystore *ue_pkcs12_keystore_create_from_files(char *certificate_path, char *private_key_path, const char *private_key_password, char *friendly_name) {
    ue_x509_certificate *certificate;
    ue_private_key *private_key;
    ue_pkcs12_keystore *keystore;

    if (!ue_x509_certificate_load_from_files(certificate_path, private_key_path, private_key_password, &certificate, &private_key)) {
        ei_stacktrace_push_msg("Failed to load certificate and private key from '%s' and '%s' files", certificate_path, private_key_path);
        return NULL;
    }

    if (!(keystore = ue_pkcs12_keystore_create(certificate, private_key, friendly_name))) {
        ue_x509_certificate_destroy(certificate);
        ue_private_key_destroy(private_key);
        ei_stacktrace_push_msg("Failed to create keystore from '%s' and '%s' files", certificate_path, private_key_path);
        return NULL;
    }

    return keystore;
}
