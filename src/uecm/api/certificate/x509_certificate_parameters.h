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

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_PARAMETERS_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_PARAMETERS_H

#include <ueum/ueum.h>

typedef struct uecm_x509_certificate_parameters uecm_x509_certificate_parameters;

uecm_x509_certificate_parameters *uecm_x509_certificate_parameters_create();

void uecm_x509_certificate_parameters_destroy(uecm_x509_certificate_parameters *parameters);

unsigned char *uecm_x509_certificate_parameters_get_serial(uecm_x509_certificate_parameters *parameters);

int uecm_x509_certificate_parameters_get_serial_length(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_bits(uecm_x509_certificate_parameters *parameters, int bits);

int uecm_x509_certificate_parameters_get_bits(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_days(uecm_x509_certificate_parameters *parameters, int days);

int uecm_x509_certificate_parameters_get_days(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_country(uecm_x509_certificate_parameters *parameters, char *country);

char *uecm_x509_certificate_parameters_get_country(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_common_name(uecm_x509_certificate_parameters *parameters, char *common_name);

char *uecm_x509_certificate_parameters_get_common_name(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_organizational_unit(uecm_x509_certificate_parameters *parameters, char *organizational_unit);

char *uecm_x509_certificate_parameters_get_oranizational_unit(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_organization(uecm_x509_certificate_parameters *parameters, char *organization);

char *uecm_x509_certificate_parameters_get_oranization(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_ca_type(uecm_x509_certificate_parameters *parameters);

char *uecm_x509_certificate_parameters_get_constraint(uecm_x509_certificate_parameters *parameters);

char *uecm_x509_certificate_parameters_get_cert_type(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_subject_key_identifier_as_hash(uecm_x509_certificate_parameters *parameters);

char *uecm_x509_certificate_parameters_get_subject_key_identifier(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_self_signed(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_is_self_signed(uecm_x509_certificate_parameters *parameters);

#endif
