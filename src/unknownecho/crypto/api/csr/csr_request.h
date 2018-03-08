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

#ifndef UNKNOWNECHO_CSR_REQUEST_H
#define UNKNOWNECHO_CSR_REQUEST_H

#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/sym_key.h>

#include <stddef.h>

unsigned char *ue_csr_build_client_request(ue_x509_certificate *certificate, ue_private_key *private_key,
    ue_public_key *ca_public_key, size_t *cipher_data_size, ue_sym_key *future_key, unsigned char *iv, size_t iv_size);

ue_x509_certificate *ue_csr_process_server_response(unsigned char *server_response, size_t server_response_size, ue_sym_key *key,
    unsigned char *iv, size_t iv_size);

unsigned char *ue_csr_build_server_response(ue_private_key *csr_private_key, ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key,
    unsigned char *client_request, size_t client_request_size, size_t *server_response_size, ue_x509_certificate **signed_certificate);

#endif
