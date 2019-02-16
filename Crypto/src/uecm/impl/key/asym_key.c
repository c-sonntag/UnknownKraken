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

#include <uecm/api/key/asym_key.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

uecm_asym_key *uecm_asym_key_create(uecm_public_key *pk, uecm_private_key *sk) {
    uecm_asym_key *akey;

    akey = NULL;

    ueum_safe_alloc(akey, uecm_asym_key, 1)
    akey->pk = pk;
    akey->sk = sk;

    return akey;
}

void uecm_asym_key_destroy(uecm_asym_key *akey){
    ueum_safe_free(akey);
}


void uecm_asym_key_destroy_all(uecm_asym_key *akey){
    if (akey) {
        uecm_public_key_destroy(akey->pk);
        uecm_private_key_destroy(akey->sk);
        ueum_safe_free(akey);
    }
}

/*bool uecm_asym_key_is_valid(uecm_asym_key *akey){
    return akey && akey->pk && akey->sk &&
        uecm_public_key_is_valid(akey->pk) &&
        uecm_private_key_is_valid(akey->sk);
}*/

bool uecm_asym_key_print(uecm_asym_key *akey, FILE *out_fd, char *passphrase) {
    if (!akey || !akey->pk || !akey->sk) {
        return false;
    }

    uecm_public_key_print(akey->pk, out_fd);
    uecm_private_key_print(akey->sk, out_fd, passphrase);

    return true;
}
