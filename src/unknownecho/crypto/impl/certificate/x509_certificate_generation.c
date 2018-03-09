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

#include <unknownecho/crypto/api/certificate/x509_certificate_generation.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/logger_manager.h>
#include <unknownecho/alloc.h>
#include <unknownecho/defines.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <stdio.h>
#include <string.h>


static bool add_ext(X509 *cert, int nid, char *value);

static RSA *rsa_keypair_gen(int bits);

static bool set_serial_number(X509 *x, unsigned char *serial_bytes, int serial_bytes_length);


bool ue_x509_certificate_generate(ue_x509_certificate_parameters *parameters, ue_x509_certificate **certificate, ue_private_key **private_key) {
    X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name;
	char *error_buffer;

	ue_check_parameter_or_return(parameters);

	x = NULL;
	pk = NULL;
	rsa = NULL;
	name = NULL;
	error_buffer = NULL;

	if (!(x = X509_new())) {
		ue_openssl_error_handling(error_buffer, "Failed to create new X509 implementation");
		return false;
	}

    if (!(rsa = rsa_keypair_gen(ue_x509_certificate_parameters_get_bits(parameters)))) {
		ue_openssl_error_handling(error_buffer, "Failed to create new RSA keypair");
		goto clean_up_failed;
	}

	if (!(*private_key = ue_private_key_create(RSA_PRIVATE_KEY, rsa, ue_x509_certificate_parameters_get_bits(parameters)))) {
		ue_stacktrace_push_msg("Failed to create private key from generated RSA");
		RSA_free(rsa);
		goto clean_up_failed;
	}

	RSA_free(rsa);

    pk = ue_private_key_get_impl(*private_key);

    if (!(*certificate = ue_x509_certificate_create_empty())) {
		ue_stacktrace_push_msg("Failed to create new X509 certificate");
		goto clean_up_failed;
	}

	/* Set to version 3 */
	X509_set_version(x, 2);

	if (!set_serial_number(x, ue_x509_certificate_parameters_get_serial(parameters), ue_x509_certificate_parameters_get_serial_length(parameters))) {
		ue_stacktrace_push_msg("Failed to set serial number to cert impl");
		goto clean_up_failed;
	}

	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)UNKNOWNECHO_DEFAULT_X509_NOT_AFTER_YEAR * ue_x509_certificate_parameters_get_days(parameters) * 3600);
	X509_set_pubkey(x, pk);

	name = X509_get_subject_name(x);

	 if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)ue_x509_certificate_parameters_get_common_name(parameters),
	 	(int)strlen(ue_x509_certificate_parameters_get_common_name(parameters)), -1, 0)) {

		 ue_openssl_error_handling(error_buffer, "Failed to add CN to certificate");
		 goto clean_up_failed;
	 }

	if (ue_x509_certificate_parameters_get_country(parameters)) {
		if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)ue_x509_certificate_parameters_get_country(parameters),
			(int)strlen(ue_x509_certificate_parameters_get_country(parameters)), -1, 0)) {

			ue_openssl_error_handling(error_buffer, "Failed to add C to certificate");
			goto clean_up_failed;
		}
	}

	/**
	 * If it's self signed set the issuer name to be the same as the
 	 * subject.
	 */
	if (ue_x509_certificate_parameters_is_self_signed(parameters)) {
		if (!X509_set_issuer_name(x, name)) {
			ue_openssl_error_handling(error_buffer, "Failed to set issuer name for self signed cert");
			goto clean_up_failed;
		}
	}

	if (ue_x509_certificate_parameters_get_constraint(parameters)) {
		if (!add_ext(x, NID_basic_constraints, ue_x509_certificate_parameters_get_constraint(parameters))) {
			ue_stacktrace_push_msg("Failed to add constraint ext to cert");
			goto clean_up_failed;
		}
	}

	if (!add_ext(x, NID_subject_key_identifier, ue_x509_certificate_parameters_get_subject_key_identifier(parameters))) {
		ue_stacktrace_push_msg("Failed to add subject key identifier ext to cert");
		goto clean_up_failed;
	}

	/* Netscape specific extensions */
	if (!add_ext(x, NID_netscape_cert_type, ue_x509_certificate_parameters_get_cert_type(parameters))) {
		ue_stacktrace_push_msg("Failed to add cert type ext to cert");
		goto clean_up_failed;
	}

	if (!X509_sign(x, pk, EVP_get_digestbyname(UNKNOWNECHO_DEFAULT_DIGEST_NAME))) {
		ue_openssl_error_handling(error_buffer, "Failed to sign cert");
		goto clean_up_failed;
    }

    ue_x509_certificate_set_impl(*certificate, x);

	return true;

clean_up_failed:
	ue_x509_certificate_destroy(*certificate);
	X509_free(x);
	return false;
}

bool ue_x509_certificate_print_pair(ue_x509_certificate *certificate, ue_private_key *private_key, char *certificate_file_name,
	char *private_key_file_name) {

	bool result;
	FILE *private_key_fd, *certificate_fd;

	ue_check_parameter_or_return(certificate);
	ue_check_parameter_or_return(private_key);
	ue_check_parameter_or_return(certificate_file_name);
	ue_check_parameter_or_return(private_key_file_name);

	result = false;
	private_key_fd = NULL;
	certificate_fd = NULL;

	if (!(certificate_fd = fopen(certificate_file_name, "wb"))) {
		ue_stacktrace_push_errno();
		goto clean_up;
	}

    if (!(private_key_fd = fopen(private_key_file_name, "wb"))) {
		ue_stacktrace_push_errno();
		goto clean_up;
	}

    if (!ue_x509_certificate_print(certificate, certificate_fd)) {
		ue_stacktrace_push_msg("Failed to print certificate to '%s' file", certificate_file_name);
		goto clean_up;
	}

    if (!ue_private_key_print(private_key, private_key_fd)) {
		ue_stacktrace_push_msg("Failed to print private key to '%s' file", private_key_file_name);
		goto clean_up;
	}

	result = true;

clean_up:
	ue_safe_fclose(certificate_fd);
	ue_safe_fclose(private_key_fd);
	return result;
}

/*static int genrsa_callback(int p, int n, BN_GENCB *cb)
{
    char c = '*';

    if (p == 0) c = '.';
    if (p == 1) c = '+';
    if (p == 2) c = '*';
    if (p == 3) c = '\n';
    BIO_write(cb->arg, &c, 1);
    (void)BIO_flush(cb->arg);
    return 1;
}*/

/*static void callback(int p, int n, void *arg) {
	char c = 'B';

	if (p == 0) {
        c = '.';
    }
	if (p == 1) {
        c='+';
    }
	if (p == 2) {
        c='*';
    }
	if (p == 3) {
        c='\n';
    }

	fputc(c, ue_logger_get_fp(ue_logger_manager_get_logger()));
}*/

static RSA *rsa_keypair_gen(int bits) {
	RSA *ue_rsa_key_pair;
	unsigned long e;
	int ret;
	BIGNUM *bne;
    char *error_buffer;
    //BN_GENCB cb;

	ue_rsa_key_pair = NULL;
	bne = NULL;
    e = RSA_F4;
    error_buffer = NULL;
    //BN_GENCB_set(&cb, callback, bio_err);

    if (bits != 2048 && bits != 4096) {
    	return NULL;
    }

	if (!(ue_rsa_key_pair = RSA_new())) {
        ue_openssl_error_handling(error_buffer, "RSA_new");
        return NULL;
    }

	if (!(bne = BN_new())) {
        ue_openssl_error_handling(error_buffer, "BN_new");
        RSA_free(ue_rsa_key_pair);
        return NULL;
    }

    if ((ret = BN_set_word(bne, e)) != 1) {
        ue_openssl_error_handling(error_buffer, "BN_set_word");
    	RSA_free(ue_rsa_key_pair);
        BN_clear_free(bne);
        return NULL;
    }

    if (!(ret = RSA_generate_key_ex(ue_rsa_key_pair, bits, bne, NULL))) {
        ue_openssl_error_handling(error_buffer, "RSA_generate_key_ex");
        RSA_free(ue_rsa_key_pair);
        BN_clear_free(bne);
        return NULL;
    }

    BN_clear_free(bne);

	return ue_rsa_key_pair;
}

static bool add_ext(X509 *cert, int nid, char *value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;

	/**
	 * This sets the 'context' of the extensions without
	 * configuration database
	 */
	X509V3_set_ctx_nodb(&ctx);

	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

	if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value))) {
		ue_stacktrace_push_msg("Ext returned is null")
		return false;
	}

	if (!X509_add_ext(cert, ex, -1)) {
		ue_stacktrace_push_msg("Failed to add ext to cert");
		X509_EXTENSION_free(ex);
		return false;
	}

	X509_EXTENSION_free(ex);

	return true;
}

static bool set_serial_number(X509 *x, unsigned char *serial_bytes, int serial_bytes_length) {
	bool result;
	BIGNUM *bn;
	ASN1_INTEGER *serial;
	char *error_buffer;

	ue_check_parameter_or_return(x);
	ue_check_parameter_or_return(serial_bytes);
	ue_check_parameter_or_return(serial_bytes_length > 0);

	result = false;
	bn = BN_new();
	serial = ASN1_INTEGER_new();
	error_buffer = NULL;

	BN_bin2bn(serial_bytes, serial_bytes_length, bn);
	BN_to_ASN1_INTEGER(bn, serial);
	if (!X509_set_serialNumber(x, serial)) {
		ue_openssl_error_handling(error_buffer, "X509_set_serialNumber");
		goto clean_up;
	}

	result = true;

clean_up:
	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return result;
}
