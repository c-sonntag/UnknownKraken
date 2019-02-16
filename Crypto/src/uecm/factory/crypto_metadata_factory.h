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

#ifndef UNKNOWNECHOCRYPTOMODULE_CRYPTO_METADATA_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_CRYPTO_METADATA_FACTORY_H

#include <uecm/api/crypto_metadata.h>

uecm_crypto_metadata *uecm_crypto_metadata_create_default();

uecm_crypto_metadata *uecm_crypto_metadata_write_if_not_exist(const char *private_folder, const char *
    certificates_folder, const char *uid, const char *password);

#endif
