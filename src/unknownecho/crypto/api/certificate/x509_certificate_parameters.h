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

/**
 *  @file      x509_certificate_parameters.h
 *  @brief     Structure to store parameters of an X509 certificate, to generate a parameterized certificate.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       x509_certificate_generation.h
 */

#ifndef UNKNOWNECHO_X509_CERTIFICATE_PARAMETERS_H
#define UNKNOWNECHO_X509_CERTIFICATE_PARAMETERS_H

#include <unknownecho/bool.h>

typedef struct ue_x509_certificate_parameters ue_x509_certificate_parameters;

ue_x509_certificate_parameters *ue_x509_certificate_parameters_create();

void ue_x509_certificate_parameters_destroy(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_set_serial(ue_x509_certificate_parameters *parameters, int serial);

int ue_x509_certificate_parameters_get_serial(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_set_bits(ue_x509_certificate_parameters *parameters, int bits);

int ue_x509_certificate_parameters_get_bits(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_set_days(ue_x509_certificate_parameters *parameters, int days);

int ue_x509_certificate_parameters_get_days(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_set_country(ue_x509_certificate_parameters *parameters, char *country);

char *ue_x509_certificate_parameters_get_country(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_set_common_name(ue_x509_certificate_parameters *parameters, char *common_name);

char *ue_x509_certificate_parameters_get_common_name(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_set_organizational_unit(ue_x509_certificate_parameters *parameters, char *organizational_unit);

char *ue_x509_certificate_parameters_get_oranizational_unit(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_set_organization(ue_x509_certificate_parameters *parameters, char *organization);

char *ue_x509_certificate_parameters_get_oranization(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_set_ca_type(ue_x509_certificate_parameters *parameters);

char *ue_x509_certificate_parameters_get_constraint(ue_x509_certificate_parameters *parameters);

char *ue_x509_certificate_parameters_get_cert_type(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_set_subject_key_identifier_as_hash(ue_x509_certificate_parameters *parameters);

char *ue_x509_certificate_parameters_get_subject_key_identifier(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_set_self_signed(ue_x509_certificate_parameters *parameters);

bool ue_x509_certificate_parameters_is_self_signed(ue_x509_certificate_parameters *parameters);

#endif
