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

/**
 *  @file      x509_certificate_parameters.h
 *  @brief     Structure to store parameters of an X509 certificate, to generate a parameterized certificate.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @see       x509_certificate_generation.h
 */

#ifndef UnknownKrakenCrypto_X509_CERTIFICATE_PARAMETERS_H
#define UnknownKrakenCrypto_X509_CERTIFICATE_PARAMETERS_H

#include <uk/utils/ueum.h>

typedef struct uk_crypto_x509_certificate_parameters uk_crypto_x509_certificate_parameters;

uk_crypto_x509_certificate_parameters *uk_crypto_x509_certificate_parameters_create();

void uk_crypto_x509_certificate_parameters_destroy(uk_crypto_x509_certificate_parameters *parameters);

unsigned char *uk_crypto_x509_certificate_parameters_get_serial(uk_crypto_x509_certificate_parameters *parameters);

int uk_crypto_x509_certificate_parameters_get_serial_length(uk_crypto_x509_certificate_parameters *parameters);

bool uk_crypto_x509_certificate_parameters_set_bits(uk_crypto_x509_certificate_parameters *parameters, int bits);

int uk_crypto_x509_certificate_parameters_get_bits(uk_crypto_x509_certificate_parameters *parameters);

bool uk_crypto_x509_certificate_parameters_set_days(uk_crypto_x509_certificate_parameters *parameters, int days);

int uk_crypto_x509_certificate_parameters_get_days(uk_crypto_x509_certificate_parameters *parameters);

bool uk_crypto_x509_certificate_parameters_set_country(uk_crypto_x509_certificate_parameters *parameters, char *country);

char *uk_crypto_x509_certificate_parameters_get_country(uk_crypto_x509_certificate_parameters *parameters);

bool uk_crypto_x509_certificate_parameters_set_common_name(uk_crypto_x509_certificate_parameters *parameters, char *common_name);

char *uk_crypto_x509_certificate_parameters_get_common_name(uk_crypto_x509_certificate_parameters *parameters);

bool uk_crypto_x509_certificate_parameters_set_organizational_unit(uk_crypto_x509_certificate_parameters *parameters, char *organizational_unit);

char *uk_crypto_x509_certificate_parameters_get_oranizational_unit(uk_crypto_x509_certificate_parameters *parameters);

bool uk_crypto_x509_certificate_parameters_set_organization(uk_crypto_x509_certificate_parameters *parameters, char *organization);

char *uk_crypto_x509_certificate_parameters_get_oranization(uk_crypto_x509_certificate_parameters *parameters);

bool uk_crypto_x509_certificate_parameters_set_ca_type(uk_crypto_x509_certificate_parameters *parameters);

char *uk_crypto_x509_certificate_parameters_get_constraint(uk_crypto_x509_certificate_parameters *parameters);

char *uk_crypto_x509_certificate_parameters_get_cert_type(uk_crypto_x509_certificate_parameters *parameters);

bool uk_crypto_x509_certificate_parameters_set_subject_key_identifier_as_hash(uk_crypto_x509_certificate_parameters *parameters);

char *uk_crypto_x509_certificate_parameters_get_subject_key_identifier(uk_crypto_x509_certificate_parameters *parameters);

bool uk_crypto_x509_certificate_parameters_set_self_signed(uk_crypto_x509_certificate_parameters *parameters);

bool uk_crypto_x509_certificate_parameters_is_self_signed(uk_crypto_x509_certificate_parameters *parameters);

#endif
