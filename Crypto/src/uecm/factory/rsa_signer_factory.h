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
 *  @file      rsa_signer_factory.h
 *  @brief     Factory to create RSA signer from key pair.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_RSA_SIGNER_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_RSA_SIGNER_FACTORY_H

#include <uecm/api/signature/signer.h>
#include <uecm/api/key/public_key.h>
#include <uecm/api/key/private_key.h>
#include <uecm/api/key/asym_key.h>

uecm_signer *uecm_rsa_signer_create(uecm_public_key *pk, uecm_private_key *sk, const char *digest_name);

uecm_signer *uecm_rsa_signer_create_default(uecm_public_key *pk, uecm_private_key *sk);

uecm_signer *uecm_rsa_signer_create_sha256(uecm_public_key *pk, uecm_private_key *sk);

uecm_signer *uecm_rsa_signer_create_from_pair(uecm_asym_key *akey, const char *digest_name);

uecm_signer *uecm_rsa_signer_create_default_from_pair(uecm_asym_key *akey);

uecm_signer *uecm_rsa_signer_create_sha256_from_pair(uecm_asym_key *akey);

#endif
