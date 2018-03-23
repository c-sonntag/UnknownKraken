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
 *  @file      x509_certificate_generation.h
 *  @brief     Generate X509 certificates.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       x509_certificate.h
 *  @see       x509_certificate_parameters.h
 *  @todo      add callback for RSA generation
 */

#ifndef UNKNOWNECHO_X509_CERTFICATE_GENERATION_H
#define UNKNOWNECHO_X509_CERTFICATE_GENERATION_H

#include <unknownecho/bool.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_parameters.h>
#include <unknownecho/crypto/api/key/private_key.h>

#include <stddef.h>

bool ue_x509_certificate_generate(ue_x509_certificate_parameters *parameters, ue_x509_certificate **certificate, ue_private_key **private_key);

bool ue_x509_certificate_print_pair(ue_x509_certificate *certificate, ue_private_key *private_key,
    char *certificate_file_name, char *private_key_file_name, unsigned char *passphrase, size_t passphrase_size);

#endif
