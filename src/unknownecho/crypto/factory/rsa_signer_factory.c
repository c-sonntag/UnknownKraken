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

#include <unknownecho/crypto/factory/rsa_signer_factory.h>
#include <unknownecho/crypto/factory/hasher_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>

ue_signer *ue_rsa_signer_create(ue_public_key *pk, ue_private_key *sk, const char *digest_name) {
	ue_signer *signer;

	if (!pk) {
		ue_stacktrace_push_msg("Specified public key is null");
		return NULL;
	}

	if (!sk) {
		ue_stacktrace_push_msg("Specified private key is null");
		return NULL;
	}

	if (!(signer = ue_signer_create(digest_name))) {
		ue_stacktrace_push_msg("Failed to create signer");
		return NULL;
	}

	ue_signer_set_public_key(signer, pk);
	ue_signer_set_private_key(signer, sk);

	return signer;
}

ue_signer *ue_rsa_signer_create_default(ue_public_key *pk, ue_private_key *sk) {
	return ue_rsa_signer_create_sha256(pk, sk);
}

ue_signer *ue_rsa_signer_create_sha256(ue_public_key *pk, ue_private_key *sk) {
	return ue_rsa_signer_create(pk, sk, "sha256");
}

ue_signer *ue_rsa_signer_create_from_pair(ue_asym_key *akey, const char *digest_name) {
	return ue_rsa_signer_create(akey->pk, akey->sk, digest_name);
}

ue_signer *ue_rsa_signer_create_default_from_pair(ue_asym_key *akey) {
	return ue_rsa_signer_create_default(akey->pk, akey->sk);
}

ue_signer *ue_rsa_signer_create_sha256_from_pair(ue_asym_key *akey) {
	return ue_rsa_signer_create_sha256(akey->pk, akey->sk);
}
