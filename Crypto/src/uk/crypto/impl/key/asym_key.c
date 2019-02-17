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

#include <uk/crypto/api/key/asym_key.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

uk_crypto_asym_key *uk_crypto_asym_key_create(uk_crypto_public_key *pk, uk_crypto_private_key *sk) {
    uk_crypto_asym_key *akey;

    akey = NULL;

    uk_utils_safe_alloc(akey, uk_crypto_asym_key, 1)
    akey->pk = pk;
    akey->sk = sk;

    return akey;
}

void uk_crypto_asym_key_destroy(uk_crypto_asym_key *akey){
    uk_utils_safe_free(akey);
}


void uk_crypto_asym_key_destroy_all(uk_crypto_asym_key *akey){
    if (akey) {
        uk_crypto_public_key_destroy(akey->pk);
        uk_crypto_private_key_destroy(akey->sk);
        uk_utils_safe_free(akey);
    }
}

/*bool uk_crypto_asym_key_is_valid(uk_crypto_asym_key *akey){
    return akey && akey->pk && akey->sk &&
        uk_crypto_public_key_is_valid(akey->pk) &&
        uk_crypto_private_key_is_valid(akey->sk);
}*/

bool uk_crypto_asym_key_print(uk_crypto_asym_key *akey, FILE *out_fd, char *passphrase) {
    if (!akey || !akey->pk || !akey->sk) {
        return false;
    }

    uk_crypto_public_key_print(akey->pk, out_fd);
    uk_crypto_private_key_print(akey->sk, out_fd, passphrase);

    return true;
}
