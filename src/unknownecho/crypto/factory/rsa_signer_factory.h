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
 *  @file      rsa_signer_factory.h
 *  @brief     Factory to create RSA signer from key pair.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_RSA_SIGNER_FACTORY_H
#define UNKNOWNECHO_RSA_SIGNER_FACTORY_H

#include <unknownecho/crypto/api/signature/signer.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/key/asym_key.h>

ue_signer *ue_rsa_signer_create(ue_public_key *pk, ue_private_key *sk, const char *digest_name);

ue_signer *ue_rsa_signer_create_default(ue_public_key *pk, ue_private_key *sk);

ue_signer *ue_rsa_signer_create_sha256(ue_public_key *pk, ue_private_key *sk);

ue_signer *ue_rsa_signer_create_from_pair(ue_asym_key *akey, const char *digest_name);

ue_signer *ue_rsa_signer_create_default_from_pair(ue_asym_key *akey);

ue_signer *ue_rsa_signer_create_sha256_from_pair(ue_asym_key *akey);

#endif
