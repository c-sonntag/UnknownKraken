/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
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

/**
 *  @file      x509_certificate_sign.h
 *  @brief     Sign, verify X509 certificates.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @see       x509_certificate.h
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_SIGN_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_SIGN_H

#include <uecm/api/certificate/x509_certificate.h>
#include <uecm/api/certificate/x509_csr.h>
#include <uecm/api/key/private_key.h>
#include <ueum/ueum.h>

uecm_x509_certificate *uecm_x509_certificate_sign_from_csr(uecm_x509_csr *csr, uecm_x509_certificate *ca_certificate, uecm_private_key *ca_private_key);

/**
 *  @todo add chain certificates verification
 */
bool uecm_x509_certificate_verify(uecm_x509_certificate *signed_certificate, uecm_x509_certificate *ca_certificate);

#endif
