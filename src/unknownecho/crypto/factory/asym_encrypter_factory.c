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

#include <unknownecho/crypto/factory/asym_encrypter_factory.h>
#include <unknownecho/crypto/api/encryption/asym_encrypter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

ue_asym_encrypter *ue_asym_encrypter_rsa_pkcs1_create(ue_public_key *pk, ue_private_key *sk) {
	ue_asym_encrypter *encrypter;

	encrypter = ue_asym_encrypter_create();
	ue_asym_encrypter_init(encrypter, "RSA-PKCS1");
	if (pk) {
		ue_asym_encrypter_set_pk(encrypter, pk);
	}
	if (sk) {
		ue_asym_encrypter_set_sk(encrypter, sk);
	}

	return encrypter;
}

ue_asym_encrypter *ue_asym_encrypter_rsa_pkcs1_oaep_create(ue_public_key *pk, ue_private_key *sk) {
	ue_asym_encrypter *encrypter;

	encrypter = ue_asym_encrypter_create();
	ue_asym_encrypter_init(encrypter, "RSA-PKCS1-OAEP");
	if (pk) {
		ue_asym_encrypter_set_pk(encrypter, pk);
	}
	if (sk) {
		ue_asym_encrypter_set_sk(encrypter, sk);
	}

	return encrypter;
}

ue_asym_encrypter *ue_asym_encrypter_default_create(ue_public_key *pk, ue_private_key *sk) {
	return ue_asym_encrypter_rsa_pkcs1_oaep_create(pk, sk);
}
