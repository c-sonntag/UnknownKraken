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

/**
 *  @file      asym_key.h
 *  @brief     Asymmetric Key structure.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_ASYM_KEY_H
#define UNKNOWNECHOCRYPTOMODULE_ASYM_KEY_H

#include <uecm/api/key/public_key.h>
#include <uecm/api/key/private_key.h>
#include <ueum/ueum.h>

#include <stdio.h>
#include <stddef.h>

typedef struct {
    uecm_public_key *pk;
    uecm_private_key *sk;
} uecm_asym_key;

uecm_asym_key *uecm_asym_key_create(uecm_public_key *pk, uecm_private_key *sk);

void uecm_asym_key_destroy(uecm_asym_key *akey);

void uecm_asym_key_destroy_all(uecm_asym_key *akey);

//bool uecm_asym_key_is_valid(uecm_asym_key *akey);

bool uecm_asym_key_print(uecm_asym_key *akey, FILE *out_fd, char *passphrase);

#endif
