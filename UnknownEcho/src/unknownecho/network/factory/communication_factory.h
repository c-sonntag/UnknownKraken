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

#ifndef UNKNOWNECHO_COMMUNICATION_FACTORY_H
#define UNKNOWNECHO_COMMUNICATION_FACTORY_H

#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/network/api/communication/communication_type.h>

ue_communication_context *ue_communication_build_from_type(ue_communication_type type);

ue_communication_context *ue_communication_build_socket();

void *ue_communication_build_client_connection_parameters(ue_communication_context *context,  int count, ...);

void *ue_communication_build_server_parameters(ue_communication_context *context,  int count, ...);

const char *ue_communication_get_default_type();

#endif
