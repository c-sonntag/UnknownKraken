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

#include <unknownecho/init.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

static bool errorInterceptor_initialized = false;
static bool crypto_initialized = false;

int ue_init() {
    if (!errorInterceptor_initialized) {
        errorInterceptor_initialized = ei_init();
    }

    if (errorInterceptor_initialized && !crypto_initialized) {
        crypto_initialized = uecm_crypto_init();
    }

    return errorInterceptor_initialized && crypto_initialized;
}

void ue_uninit() {
    if (crypto_initialized) {
        uecm_crypto_uninit();
    }

    if (errorInterceptor_initialized) {
        ei_uninit();
    }
}
