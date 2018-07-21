/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
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
