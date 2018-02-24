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

#include <unknownecho/crypto/factory/hasher_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>

ue_hasher *ue_hasher_sha256_create() {
    ue_hasher *h;

    if (!(h = ue_hasher_create())) {
        ue_stacktrace_push_msg("Failed to create ue_hasher");
        return NULL;
    }

    if (!(ue_hasher_init(h, "SHA-256"))) {
        ue_stacktrace_push_msg("Failed to initialize ue_hasher with SHA-256 algorithm");
        ue_hasher_destroy(h);
        return NULL;
    }

    return h;
}

ue_hasher *ue_hasher_default_create() {
    return ue_hasher_sha256_create();
}
