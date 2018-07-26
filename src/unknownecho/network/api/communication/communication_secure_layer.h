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

#ifndef UNKNOWNECHO_COMMUNICATION_SECURE_LAYER_H
#define UNKNOWNECHO_COMMUNICATION_SECURE_LAYER_H

#include <unknownecho/network/api/communication/communication_context.h>
#include <uecm/uecm.h>
#include <ueum/ueum.h>

void *ue_communication_secure_layer_build_client(ue_communication_context *context, int count, ...);

void *ue_communication_secure_layer_build_server(ue_communication_context *context, int count, ...);

bool ue_communication_secure_layer_destroy(ue_communication_context *context, void *csl);

uecm_pkcs12_keystore *ue_communication_secure_layer_get_keystore(ue_communication_context *context, void *csl);

#endif
