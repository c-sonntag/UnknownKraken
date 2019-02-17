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

#ifndef UnknownKrakenUnknownEcho_COMMUNICATION_FACTORY_H
#define UnknownKrakenUnknownEcho_COMMUNICATION_FACTORY_H

#include <uk/unknownecho/network/api/communication/communication_context.h>
#include <uk/unknownecho/network/api/communication/communication_type.h>

uk_ue_communication_context *uk_ue_communication_build_from_type(uk_ue_communication_type type);

uk_ue_communication_context *uk_ue_communication_build_socket();

void *uk_ue_communication_build_client_connection_parameters(uk_ue_communication_context *context,  int count, ...);

void *uk_ue_communication_build_server_parameters(uk_ue_communication_context *context,  int count, ...);

const char *uk_ue_communication_get_default_type();

#endif
