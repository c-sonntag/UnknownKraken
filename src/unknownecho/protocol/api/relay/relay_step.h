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

#ifndef UNKNWOWNECHO_RELAY_STEP_H
#define UNKNWOWNECHO_RELAY_STEP_H

#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <ueum/ueum.h>

#include <stdio.h>

ue_relay_step *ue_relay_step_create(ue_communication_metadata *target_communication_metadata,
    uecm_crypto_metadata *our_crypto_metadata, uecm_crypto_metadata *target_crypto_metadata);

ue_relay_step *ue_relay_step_create_from_step(ue_relay_step *step);

ue_relay_step **ue_relay_steps_create(int step_number, ...);

void ue_relay_step_destroy(ue_relay_step *step);

void ue_relay_step_destroy_all(ue_relay_step *step);

ue_communication_metadata *ue_relay_step_get_target_communication_metadata(ue_relay_step *step);

uecm_crypto_metadata *ue_relay_step_get_our_crypto_metadata(ue_relay_step *step);

uecm_crypto_metadata *ue_relay_step_get_target_crypto_metadata(ue_relay_step *step);

void ue_relay_step_print(ue_relay_step *step, FILE *fd);

bool ue_relay_step_is_valid(ue_relay_step *step);

#endif
