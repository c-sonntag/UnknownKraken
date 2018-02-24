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
 *  @file      x509_certificate.h
 *  @brief     Structure to represent an X509 certificate.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       https://en.wikipedia.org/wiki/X.509
 */

#ifndef UNKNOWNECHO_X509_CERTIFICATE_H
#define UNKNOWNECHO_X509_CERTIFICATE_H

#include <unknownecho/bool.h>
#include <unknownecho/crypto/api/key/private_key.h>

#include <stdio.h>
#include <stddef.h>

typedef struct ue_x509_certificate ue_x509_certificate;

ue_x509_certificate *ue_x509_certificate_create_empty();

bool ue_x509_certificate_load_from_file(const char *file_name, ue_x509_certificate **certificate);

bool ue_x509_certificate_load_from_files(const char *cert_file_name, const char *key_file_name, const char *password, ue_x509_certificate **certificate, ue_private_key **private_key);

ue_x509_certificate *ue_x509_certificate_load_from_bytes(unsigned char *data, size_t data_size);

void ue_x509_certificate_destroy(ue_x509_certificate *certificate);

void *ue_x509_certificate_get_impl(ue_x509_certificate *certificate);

bool ue_x509_certificate_set_impl(ue_x509_certificate *certificate, void *impl);

bool ue_x509_certificate_equals(ue_x509_certificate *c1, ue_x509_certificate *c2);

bool ue_x509_certificate_print(ue_x509_certificate *certificate, FILE *out_fd);

char *ue_x509_certificate_to_pem_string(ue_x509_certificate *certificate);

#endif
