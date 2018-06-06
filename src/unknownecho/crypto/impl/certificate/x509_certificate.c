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

#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <ei/ei.h>
#include <unknownecho/alloc.h>

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <stdlib.h>
#include <string.h>
#include <stddef.h>


struct ue_x509_certificate {
	X509 *impl;
};


static bool load_certificate_pair(const char *cert_file_name, const char *private_key_file_name, const char *password, X509 **certificate, EVP_PKEY **private_key);


ue_x509_certificate *ue_x509_certificate_create_empty() {
	ue_x509_certificate *certificate;

	ue_safe_alloc(certificate, ue_x509_certificate, 1);
	certificate->impl = NULL;

	return certificate;
}

bool ue_x509_certificate_load_from_file(const char *file_name, ue_x509_certificate **certificate) {
	bool result;
	X509 *certificate_impl;
	BIO *bio;
	char *error_buffer;

	ei_check_parameter_or_return(file_name);

	result = false;
	certificate_impl = NULL;
	bio = NULL;
	error_buffer = NULL;

	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, file_name)) {
		ue_openssl_error_handling(error_buffer, "Failed to read file");
		goto clean_up;
	}

	if (!(certificate_impl = PEM_read_bio_X509(bio, NULL, NULL, NULL))) {
		ue_openssl_error_handling(error_buffer, "Failed to read bio as PEM");
		goto clean_up;
	}

	if (!(*certificate = ue_x509_certificate_create_empty())) {
		ei_stacktrace_push_msg("Failed to create empty x509 certificate");
		X509_free(certificate_impl);
		goto clean_up;
	}
	if (!ue_x509_certificate_set_impl(*certificate, certificate_impl)) {
		ei_stacktrace_push_msg("Failed to set x509 certificate impl to new ue_x509_certificate");
		ue_x509_certificate_destroy(*certificate);
		X509_free(certificate_impl);
		goto clean_up;
	}

	result = true;

clean_up:
	BIO_free_all(bio);
	return result;
}

bool ue_x509_certificate_load_from_files(const char *cert_file_name, const char *private_key_file_name, const char *password,
	ue_x509_certificate **certificate, ue_private_key **private_key) {

	X509 *certificate_impl;
	EVP_PKEY *private_key_impl;
	RSA *rsa;
	char *error_buffer;

	ei_check_parameter_or_return(cert_file_name);
	ei_check_parameter_or_return(private_key_file_name);

	certificate_impl = NULL;
	private_key_impl = NULL;
	rsa = NULL;
	error_buffer = NULL;

	if (!load_certificate_pair(cert_file_name, private_key_file_name, password, &certificate_impl, &private_key_impl)) {
		ei_stacktrace_push_msg("Failed to load impl certificate pair files");
		return false;
	}

	if (!(*certificate = ue_x509_certificate_create_empty())) {
		ei_stacktrace_push_msg("Failed to create empty x509 certificate");
		goto clean_up_failed;
	}
	if (!ue_x509_certificate_set_impl(*certificate, certificate_impl)) {
		ei_stacktrace_push_msg("Failed to set x509 certificate impl to new ue_x509_certificate");
		goto clean_up_failed;
	}

	if (!(rsa = EVP_PKEY_get1_RSA(private_key_impl))) {
		ue_openssl_error_handling(error_buffer, "Failed to get RSA implementation from private key impl");
		goto clean_up_failed;
	}

	if (!(*private_key = ue_private_key_create(RSA_PRIVATE_KEY, rsa, RSA_size(rsa)))) {
		ei_stacktrace_push_msg("Failed to create ue_private_key from rsa impl");
		goto clean_up_failed;
	}

    EVP_PKEY_free(private_key_impl);
	return true;

clean_up_failed:
	X509_free(certificate_impl);
	EVP_PKEY_free(private_key_impl);
	ue_x509_certificate_destroy(*certificate);
	ue_private_key_destroy(*private_key);
	return false;
}

ue_x509_certificate *ue_x509_certificate_load_from_bytes(unsigned char *data, size_t data_size) {
	ue_x509_certificate *certificate;
    BIO *bio;
    char *error_buffer;
	X509 *certificate_impl;

	ei_check_parameter_or_return(data);
	ei_check_parameter_or_return(data_size > 0);

    certificate = ue_x509_certificate_create_empty();
    bio = NULL;
    error_buffer = NULL;

    if (!(bio = BIO_new_mem_buf(data, data_size))) {
		ue_openssl_error_handling(error_buffer, "BIO_new_mem_buf");
        ue_x509_certificate_destroy(certificate);
		goto clean_up;
	}

    if (!(certificate_impl = PEM_read_bio_X509(bio, NULL, NULL, NULL))) {
		ue_openssl_error_handling(error_buffer, "PEM_read_bio_X509");
		ue_x509_certificate_destroy(certificate);
		certificate = NULL;
		goto clean_up;
	}

	ue_x509_certificate_set_impl(certificate, certificate_impl);

clean_up:
	BIO_free_all(bio);
	return certificate;
}

void ue_x509_certificate_destroy(ue_x509_certificate *certificate) {
	if (certificate) {
		if (certificate->impl) {
			X509_free(certificate->impl);
		}
		ue_safe_free(certificate);
	}
}

void *ue_x509_certificate_get_impl(ue_x509_certificate *certificate) {
	if (!certificate) {
		ei_stacktrace_push_msg("Specified certificate ptr is null");
		return NULL;
	}

	if (!certificate->impl) {
		ei_stacktrace_push_msg("Specified certificate have no implementation");
		return NULL;
	}

	return certificate->impl;
}

bool ue_x509_certificate_set_impl(ue_x509_certificate *certificate, void *impl) {
	ei_check_parameter_or_return(certificate);
	ei_check_parameter_or_return(impl);

	certificate->impl = impl;
	return true;
}

bool ue_x509_certificate_equals(ue_x509_certificate *c1, ue_x509_certificate *c2) {
	return c1 && c2 && X509_cmp(c1->impl, c2->impl) == 0;
}

/* Since I only experimented the applink error in Windows */
#if defined(_WIN32) || defined(_WIN64)

#include <openssl/applink.c>

#endif

bool ue_x509_certificate_print(ue_x509_certificate *certificate, FILE *out_fd) {
	char *error_buffer;

	ei_check_parameter_or_return(certificate);
	ei_check_parameter_or_return(out_fd);

	error_buffer = NULL;

    if (PEM_write_X509(out_fd, certificate->impl) == 0) {
		ue_openssl_error_handling(error_buffer, "PEM_write_PrivateKey");
		return false;
	}

	return true;
}

char *ue_x509_certificate_to_pem_string(ue_x509_certificate *certificate, size_t *result_size) {
    BIO *bio;
    char *pem, *error_buffer;
	size_t size;
	int result;

	ei_check_parameter_or_return(certificate);

	bio = NULL;
	pem = NULL;
	error_buffer = NULL;
    *result_size = 0;

    if (!(bio = BIO_new(BIO_s_mem()))) {
		ue_openssl_error_handling(error_buffer, "Failed to alloc new BIO");
		return NULL;
	}

    if (!PEM_write_bio_X509(bio, ue_x509_certificate_get_impl(certificate))) {
		ue_openssl_error_handling(error_buffer, "Failed to write x509 certificate as PEM");
		BIO_free_all(bio);
		return NULL;
	}

	if ((size = BIO_pending(bio)) <= 0) {
		ei_stacktrace_push_msg("Bio have an invalid size");
		BIO_free_all(bio);
		return NULL;
	}

	ue_safe_alloc(pem, char, size);

    result = BIO_read(bio, pem, size);
	if (result <= 0) {
		BIO_free_all(bio);
		ue_safe_free(pem);
		if (result == 0) {
			ei_stacktrace_push_msg("No data read because bio is empty");
		} else if (result == -1) {
			ei_stacktrace_push_msg("Reading of bio data failed with an error");
		} else if (result == -2) {
			ei_stacktrace_push_msg("This operation is not supported by this bio");
		}
		return NULL;
	}

    BIO_free_all(bio);

    *result_size = size;

	return pem;
}

static int pass_cb(char *buf, int size, int rwflag, void *u) {
     memcpy(buf, (char *)u, strlen((char *)u));
     return strlen((char *)u);
 }

static bool load_certificate_pair(const char *cert_file_name, const char *private_key_file_name, const char *password,
	X509 **certificate, EVP_PKEY **private_key) {

	BIO *bio;
	char *error_buffer;

	ei_check_parameter_or_return(cert_file_name);
	ei_check_parameter_or_return(private_key_file_name);

	bio = NULL;
	error_buffer = NULL;
	*certificate = NULL;
	*private_key = NULL;

	/* Load certificate */
	if (!(bio = BIO_new(BIO_s_file()))) {
		ue_openssl_error_handling(error_buffer, "Failed to create new BIO for certificate");
		return false;
	}

	if (!BIO_read_filename(bio, cert_file_name)) {
		ue_openssl_error_handling(error_buffer, "Failed to read certificate file");
		goto clean_up;
	}

	if (!(*certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL))) {
		ue_openssl_error_handling(error_buffer, "Failed to read BIO as PEM x509 certificate");
		goto clean_up;
	}

	BIO_free_all(bio);

	/* Load private key */
	if (!(bio = BIO_new(BIO_s_file()))) {
		ue_openssl_error_handling(error_buffer, "Failed to create new BIO for private key");
		goto clean_up;
	}

	if (!BIO_read_filename(bio, private_key_file_name)) {
		ue_openssl_error_handling(error_buffer, "Failed to read private key file");
		goto clean_up;
	}

	if (password) {
        /* @todo fix memory leak here when server user exit with ctrl+c */
		if (!(*private_key = PEM_read_bio_PrivateKey(bio, NULL, pass_cb, (void *)password))) {
			ue_openssl_error_handling(error_buffer, "Failed to read BIO as PEM private key with a password");
			goto clean_up;
		}
	} else {
		if (!(*private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL))) {
			ue_openssl_error_handling(error_buffer, "Failed to read BIO as PEM private key without a password");
			goto clean_up;
		}
	}

	BIO_free_all(bio);

	return true;

clean_up:
	BIO_free_all(bio);
	X509_free(*certificate);
	EVP_PKEY_free(*private_key);
	return false;
}
