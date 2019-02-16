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

#include <uecm/factory/rsa_signer_factory.h>
#include <uecm/factory/hasher_factory.h>
#include <ei/ei.h>

uecm_signer *uecm_rsa_signer_create(uecm_public_key *pk, uecm_private_key *sk, const char *digest_name) {
    uecm_signer *signer;

    if (!pk) {
        ei_stacktrace_push_msg("Specified public key is null");
        return NULL;
    }

    if (!sk) {
        ei_stacktrace_push_msg("Specified private key is null");
        return NULL;
    }

    if ((signer = uecm_signer_create(digest_name)) == NULL) {
        ei_stacktrace_push_msg("Failed to create signer");
        return NULL;
    }

    uecm_signer_set_public_key(signer, pk);
    uecm_signer_set_private_key(signer, sk);

    return signer;
}

uecm_signer *uecm_rsa_signer_create_default(uecm_public_key *pk, uecm_private_key *sk) {
    return uecm_rsa_signer_create_sha256(pk, sk);
}

uecm_signer *uecm_rsa_signer_create_sha256(uecm_public_key *pk, uecm_private_key *sk) {
    return uecm_rsa_signer_create(pk, sk, "sha256");
}

uecm_signer *uecm_rsa_signer_create_from_pair(uecm_asym_key *akey, const char *digest_name) {
    return uecm_rsa_signer_create(akey->pk, akey->sk, digest_name);
}

uecm_signer *uecm_rsa_signer_create_default_from_pair(uecm_asym_key *akey) {
    return uecm_rsa_signer_create_default(akey->pk, akey->sk);
}

uecm_signer *uecm_rsa_signer_create_sha256_from_pair(uecm_asym_key *akey) {
    return uecm_rsa_signer_create_sha256(akey->pk, akey->sk);
}
