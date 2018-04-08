/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#ifndef UNKNOWNECHO_COMMUNICATION_SECURE_LAYER_H
#define UNKNOWNECHO_COMMUNICATION_SECURE_LAYER_H

#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/bool.h>

void *ue_communication_secure_layer_build_client(ue_communication_context *context, int count, ...);

void *ue_communication_secure_layer_build_server(ue_communication_context *context, int count, ...);

bool ue_communication_secure_layer_destroy(ue_communication_context *context, void *csl);

ue_pkcs12_keystore *ue_communication_secure_layer_get_keystore(ue_communication_context *context, void *csl);

#endif
