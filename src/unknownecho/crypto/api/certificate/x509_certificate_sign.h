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
 *  @file      x509_certificate_sign.h
 *  @brief     Sign, verify X509 certificates.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       x509_certificate.h
 */

#ifndef UNKNOWNECHO_X509_CERTIFICATE_SIGN_H
#define UNKNOWNECHO_X509_CERTIFICATE_SIGN_H

#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/certificate/x509_csr.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

ue_x509_certificate *ue_x509_certificate_sign_from_csr(ue_x509_csr *csr, ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key);

bool ue_x509_certificate_verify(ue_x509_certificate *signed_certificate, ue_x509_certificate *ca_certificate);

#endif
