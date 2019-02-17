/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
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

#ifndef UnknownKrakenUnknownEcho_COMMUNICATION_SECURE_LAYER_H
#define UnknownKrakenUnknownEcho_COMMUNICATION_SECURE_LAYER_H

#include <uk/unknownecho/network/api/communication/communication_context.h>
#include <uk/crypto/uecm.h>
#include <uk/utils/ueum.h>

void *uk_ue_communication_secure_layer_build_client(uk_ue_communication_context *context, int count, ...);

void *uk_ue_communication_secure_layer_build_server(uk_ue_communication_context *context, int count, ...);

bool uk_ue_communication_secure_layer_destroy(uk_ue_communication_context *context, void *csl);

uk_crypto_pkcs12_keystore *uk_ue_communication_secure_layer_get_keystore(uk_ue_communication_context *context, void *csl);

#endif
