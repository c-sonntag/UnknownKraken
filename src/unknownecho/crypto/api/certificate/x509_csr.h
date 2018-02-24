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
 *  @file      x509_csr.h
 *  @brief     Structure to represent an X509 CSR (Certificate Signing Request), in order
 *             to sign issuer certificate (like a client) by CA certificate (like a server).
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       https://en.wikipedia.org/wiki/Certificate_signing_request
 */

#ifndef UNKNOWNECHO_X509_CSR_H
#define UNKNOWNECHO_X509_CSR_H

#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

#include <stdio.h>
#include <stddef.h>

typedef struct ue_x509_csr ue_x509_csr;

ue_x509_csr *ue_x509_csr_create(ue_x509_certificate *certificate, ue_private_key *private_key);

void ue_x509_csr_destroy(ue_x509_csr *csr);

bool ue_x509_csr_print(ue_x509_csr *csr, FILE *fd);

char *ue_x509_csr_to_string(ue_x509_csr *csr);

ue_x509_csr *ue_x509_string_to_csr(char *string);

ue_x509_csr *ue_x509_bytes_to_csr(unsigned char *data, size_t data_size);

ue_x509_certificate *ue_x509_csr_sign(ue_x509_csr *csr, ue_private_key *private_key);

void *ue_x509_csr_get_impl(ue_x509_csr *csr);

#endif
