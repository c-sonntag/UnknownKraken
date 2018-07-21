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

#ifndef UNKNOWNECHO_ROUTE_H
#define UNKNOWNECHO_ROUTE_H

#include <unknownecho/protocol/api/relay/relay_route_struct.h>
#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <ueum/ueum.h>

#include <stdio.h>

ue_relay_route *ue_relay_route_create(ue_relay_step **steps, int steps_number);

ue_relay_route *ue_relay_route_create_back_route(ue_relay_route *route);

void ue_relay_route_destroy(ue_relay_route *route);

void ue_relay_route_destroy_all(ue_relay_route *route);

bool ue_relay_route_is_valid(ue_relay_route *route);

ue_relay_step *ue_relay_route_get_receiver(ue_relay_route *route);

ue_relay_step *ue_relay_route_get_sender(ue_relay_route *route);

bool ue_relay_route_print(ue_relay_route *route, FILE *fd);

#endif
