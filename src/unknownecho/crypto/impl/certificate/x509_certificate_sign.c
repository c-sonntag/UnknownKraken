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

#include <unknownecho/crypto/api/certificate/x509_certificate_sign.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/errorHandling/stacktrace.h>

#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

static int generate_set_random_serial(X509 *crt) {
	/* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

ue_x509_certificate *ue_x509_certificate_sign_from_csr(ue_x509_csr *csr, ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key) {
    X509 *certificate_impl;
    ue_x509_certificate *certificate;

    certificate_impl = X509_new();
    certificate = ue_x509_certificate_create_empty();

    X509_set_version(certificate_impl, 2); /* Set version to X509v3 */

    /* Generate random 20 byte serial. */
    if (!generate_set_random_serial(certificate_impl)) goto clean_up;

    /* Set issuer to CA's subject. */
    X509_set_issuer_name(certificate_impl, X509_get_subject_name(ue_x509_certificate_get_impl(ca_certificate)));

    /* Set validity of certificate to 2 years. */
    X509_gmtime_adj(X509_get_notBefore(certificate_impl), 0);
    X509_gmtime_adj(X509_get_notAfter(certificate_impl), (long)2*365*3600);

    X509_set_subject_name(certificate_impl, X509_REQ_get_subject_name((X509_REQ *)ue_x509_csr_get_impl(csr)));
    EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(ue_x509_csr_get_impl(csr));
    X509_set_pubkey(certificate_impl, req_pubkey);
    EVP_PKEY_free(req_pubkey);

    if (X509_sign(certificate_impl, ue_private_key_get_impl(ca_private_key), EVP_sha256()) == 0) {
        goto clean_up;
    }

    ue_x509_certificate_set_impl(certificate, certificate_impl);

clean_up:
    return certificate;
}

bool ue_x509_certificate_verify(ue_x509_certificate *signed_certificate, ue_x509_certificate *ca_certificate) {
    bool result;
    X509_STORE_CTX *verify_ctx;
    X509_STORE *store;
    char *error_buffer;

    result = false;
    verify_ctx = NULL;
    store = NULL;
    error_buffer = NULL;

	if (!(store = X509_STORE_new())) {
		ue_openssl_error_handling(error_buffer, "X509_STORE_new");
        goto clean_up;
	}

    if (!(verify_ctx = X509_STORE_CTX_new())) {
        ue_openssl_error_handling(error_buffer, "X509_STORE_CTX_new");
        goto clean_up;
    }

    if (X509_STORE_add_cert(store, ue_x509_certificate_get_impl(ca_certificate)) == 0) {
        ue_openssl_error_handling(error_buffer, "X509_STORE_add_cert");
        goto clean_up;
    }

    if (X509_STORE_CTX_init(verify_ctx, store, ue_x509_certificate_get_impl(signed_certificate), NULL) == 0) {
        ue_openssl_error_handling(error_buffer, "X509_STORE_CTX_init");
        goto clean_up;
    }

    if (X509_verify_cert(verify_ctx) == 0) {
        ue_stacktrace_push_msg(X509_verify_cert_error_string(X509_STORE_CTX_get_error(verify_ctx)));
		goto clean_up;
    }

    result = true;

clean_up:
    if (verify_ctx) {
        X509_STORE_CTX_free(verify_ctx);
    }
    if (store) {
        X509_STORE_free(store);
    }
    ue_safe_free(error_buffer);
    return result;
}
