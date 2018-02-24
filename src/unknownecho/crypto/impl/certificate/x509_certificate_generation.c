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
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/logger_manager.h>
#include <unknownecho/system/alloc.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <stdio.h>
#include <string.h>


static int add_ext(X509 *cert, int nid, char *value);

//static void callback(int p, int n, void *arg);
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


static RSA *ue_rsa_keypair_gen(int bits) {
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

bool ue_x509_certificate_generate(ue_x509_certificate_parameters *parameters, ue_x509_certificate **certificate, ue_private_key **private_key) {
    X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name = NULL;

	if ((x = X509_new()) == NULL) {
		return false;
	}

    rsa = ue_rsa_keypair_gen(ue_x509_certificate_parameters_get_bits(parameters));
	*private_key = ue_private_key_create(RSA_PRIVATE_KEY, rsa, ue_x509_certificate_parameters_get_bits(parameters));
	RSA_free(rsa);

    pk = ue_private_key_get_impl(*private_key);
    *certificate = ue_x509_certificate_create_empty();

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), ue_x509_certificate_parameters_get_serial(parameters));
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60*60*24*ue_x509_certificate_parameters_get_days(parameters));
	X509_set_pubkey(x, pk);

	name = X509_get_subject_name(x);

	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */

	 X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)ue_x509_certificate_parameters_get_common_name(parameters), (int)strlen(ue_x509_certificate_parameters_get_common_name(parameters)), -1, 0);

	if (ue_x509_certificate_parameters_get_country(parameters)) {
		X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)ue_x509_certificate_parameters_get_country(parameters), (int)strlen(ue_x509_certificate_parameters_get_country(parameters)), -1, 0);
	}

	/* Its self signed so set the issuer name to be the same as the
 	 * subject.
	 */
	if (ue_x509_certificate_parameters_is_self_signed(parameters)) {
		X509_set_issuer_name(x, name);
	}

	/* Add various extensions: standard extensions */
	//add_ext(x, NID_basic_constraints, "critical, CA:FALSE");
	//add_ext(x, NID_key_usage, "critical, keyCertSign, cRLSign");

	//add_ext(x, NID_ext_key_usage, "critical, keyCertSign, cRLSign, digitalSignature, keyEncipherment");

	if (ue_x509_certificate_parameters_get_constraint(parameters)) {
		add_ext(x, NID_basic_constraints, ue_x509_certificate_parameters_get_constraint(parameters));
	}

	add_ext(x, NID_subject_key_identifier, ue_x509_certificate_parameters_get_subject_key_identifier(parameters));

	/* Some Netscape specific extensions */
	add_ext(x, NID_netscape_cert_type, ue_x509_certificate_parameters_get_cert_type(parameters));
	//add_ext(x, NID_netscape_cert_type, "sslCA");

	//add_ext(x, NID_netscape_comment, "example comment extension");


/*#ifdef CUSTOM_EXT
	// Maybe even add our own extension based on existing
	{
		int nid;
		nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		add_ext(x, nid, "example comment alias");
	}
#endif*/

	if (!X509_sign(x, pk, EVP_md5())) {
		return false;
    }

    ue_x509_certificate_set_impl(*certificate, x);

	return true;
}

bool ue_x509_certificate_print_pair(ue_x509_certificate *certificate, ue_private_key *private_key, char *certificate_file_name, char *private_key_file_name) {
	bool result;
	FILE *private_key_fd, *certificate_fd;

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

/**
 * Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */
static int add_ext(X509 *cert, int nid, char *value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;

	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) {
		return 0;
    }

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);

	return 1;
}

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

/*#define REQ_DN_C "SE"
#define REQ_DN_ST ""
#define REQ_DN_L ""
#define REQ_DN_O "Example Company"
#define REQ_DN_OU ""
#define REQ_DN_CN "VNF Application 2"*/
