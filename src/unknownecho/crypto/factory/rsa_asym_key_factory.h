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
 *  @file      rsa_asym_key_factory.h
 *  @brief     Factory to create RSA Asymmetric Key. Random, from files, from
 *             already existing certificate.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_RSA_ASYM_KEY_FACTORY_H
#define UNKNOWNECHO_RSA_ASYM_KEY_FACTORY_H

#include <unknownecho/crypto/api/key/asym_key.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>

ue_asym_key *ue_rsa_asym_key_create(int bits);

ue_public_key *ue_rsa_public_key_create_pk_from_file(char *file_path);

ue_private_key *ue_rsa_private_key_create_sk_from_file(char *file_path);

ue_asym_key *ue_rsa_asym_key_create_from_files(char *pk_file_path, char *sk_file_path);

ue_public_key *ue_rsa_public_key_from_x509_certificate(ue_x509_certificate *certificate);

ue_private_key *ue_rsa_private_key_from_key_certificate(const char *file_name);

#endif
