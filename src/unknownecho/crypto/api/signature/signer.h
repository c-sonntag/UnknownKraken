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
 *  @file      signer.h
 *  @brief     Signer structure that sign/verify binary data.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_SIGNER_H
#define UNKNOWNECHO_SIGNER_H

#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct ue_signer ue_signer;

ue_signer *ue_signer_create(const char *digest_name);

void ue_signer_destroy(ue_signer *signer);

bool ue_signer_set_public_key(ue_signer *signer, ue_public_key *public_key);

bool ue_signer_set_private_key(ue_signer *signer, ue_private_key *private_key);

bool ue_signer_sign_buffer(ue_signer *signer, const unsigned char *buf, size_t buf_length, unsigned char **signature, size_t *signature_length);

bool ue_signer_verify_buffer(ue_signer *signer, const unsigned char *buf, size_t buf_length, unsigned char *signature, size_t signature_length);

#endif
