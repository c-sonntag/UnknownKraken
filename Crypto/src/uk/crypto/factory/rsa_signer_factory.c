/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <uk/crypto/factory/rsa_signer_factory.h>
#include <uk/crypto/factory/hasher_factory.h>
#include <uk/utils/ei.h>

uk_crypto_signer *uk_crypto_rsa_signer_create(uk_crypto_public_key *pk, uk_crypto_private_key *sk, const char *digest_name) {
    uk_crypto_signer *signer;

    if (!pk) {
        uk_utils_stacktrace_push_msg("Specified public key is null");
        return NULL;
    }

    if (!sk) {
        uk_utils_stacktrace_push_msg("Specified private key is null");
        return NULL;
    }

    if ((signer = uk_crypto_signer_create(digest_name)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create signer");
        return NULL;
    }

    uk_crypto_signer_set_public_key(signer, pk);
    uk_crypto_signer_set_private_key(signer, sk);

    return signer;
}

uk_crypto_signer *uk_crypto_rsa_signer_create_default(uk_crypto_public_key *pk, uk_crypto_private_key *sk) {
    return uk_crypto_rsa_signer_create_sha256(pk, sk);
}

uk_crypto_signer *uk_crypto_rsa_signer_create_sha256(uk_crypto_public_key *pk, uk_crypto_private_key *sk) {
    return uk_crypto_rsa_signer_create(pk, sk, "sha256");
}

uk_crypto_signer *uk_crypto_rsa_signer_create_from_pair(uk_crypto_asym_key *akey, const char *digest_name) {
    return uk_crypto_rsa_signer_create(akey->pk, akey->sk, digest_name);
}

uk_crypto_signer *uk_crypto_rsa_signer_create_default_from_pair(uk_crypto_asym_key *akey) {
    return uk_crypto_rsa_signer_create_default(akey->pk, akey->sk);
}

uk_crypto_signer *uk_crypto_rsa_signer_create_sha256_from_pair(uk_crypto_asym_key *akey) {
    return uk_crypto_rsa_signer_create_sha256(akey->pk, akey->sk);
}
