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
 *  @file      x509_certificate_factory.h
 *  @brief     Factory to create signed or self-signed X509 certificate.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_X509_CERTIFICATE_FACTORY_H
#define UNKNOWNECHO_X509_CERTIFICATE_FACTORY_H

#include <unknownecho/bool.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/private_key.h>

bool ue_x509_certificate_generate_self_signed_ca(char *C, char *CN, ue_x509_certificate **certificate, ue_private_key **private_key);

bool ue_x509_certificate_generate_signed(ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key,
    char *C, char *CN, ue_x509_certificate **certificate, ue_private_key **private_key);

#endif
