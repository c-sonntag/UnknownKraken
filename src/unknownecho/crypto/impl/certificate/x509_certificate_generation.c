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

static int generate_key_csr(EVP_PKEY **key, char *C, char *CN, X509_REQ **req);

static int generate_set_random_serial(X509 *crt);

static int generate_signed_key_pair(X509 *ca_crt, EVP_PKEY *ca_key, char *C, char *CN, X509 **crt, EVP_PKEY **key);

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
	X509_NAME_add_entry_by_txt(name, "C",
				MBSTRING_ASC, (unsigned char *)ue_x509_certificate_parameters_get_country(parameters), (int)strlen(ue_x509_certificate_parameters_get_country(parameters)), -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN",
				MBSTRING_ASC, (unsigned char *)ue_x509_certificate_parameters_get_common_name(parameters), (int)strlen(ue_x509_certificate_parameters_get_common_name(parameters)), -1, 0);

	/* Its self signed so set the issuer name to be the same as the
 	 * subject.
	 */
	if (ue_x509_certificate_parameters_is_self_signed(parameters)) {
		X509_set_issuer_name(x, name);
	}

	/* Add various extensions: standard extensions */
	//add_ext(x, NID_basic_constraints, "critical, CA:TRUE");
	//add_ext(x, NID_key_usage, "critical, keyCertSign, cRLSign");

	if (ue_x509_certificate_parameters_get_constraint(parameters)) {
		add_ext(x, NID_basic_constraints, ue_x509_certificate_parameters_get_constraint(parameters));
	}

	add_ext(x, NID_subject_key_identifier, ue_x509_certificate_parameters_get_subject_key_identifier(parameters));

	/* Some Netscape specific extensions */
	add_ext(x, NID_netscape_cert_type, ue_x509_certificate_parameters_get_cert_type(parameters));

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

bool ue_x509_certificate_generate_self_signed_ca(char *C, char *CN, ue_x509_certificate **certificate, ue_private_key **private_key) {
	bool result;
	ue_x509_certificate_parameters *parameters;
    ue_x509_certificate *certificate_impl;
    ue_private_key *private_key_impl;

	result = false;
	parameters = NULL;
	certificate_impl = NULL;
	private_key_impl = NULL;

	if (!(parameters = ue_x509_certificate_parameters_create())) {
		ue_stacktrace_push_msg("Failed to create x509 parameters structure");
		return false;
	}

    if (!ue_x509_certificate_parameters_set_country(parameters, C)) {
		ue_stacktrace_push_msg("Failed to set C to x509 parameters");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_common_name(parameters, CN)) {
		ue_stacktrace_push_msg("Failed to set CN to x509 parameters");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_ca_type(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate as ca type");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_subject_key_identifier_as_hash(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate subject key identifier as hash");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_self_signed(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate as self signed");
		goto clean_up;
	}

    if (!ue_x509_certificate_generate(parameters, &certificate_impl, &private_key_impl)) {
		ue_stacktrace_push_msg("Failed to generate certificate and relative private key");
		goto clean_up;
	}

	result = true;
	*certificate = certificate_impl;
	*private_key = private_key_impl;

clean_up:
    ue_x509_certificate_parameters_destroy(parameters);
	return result;
}

bool ue_x509_certificate_generate_signed(ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key,
    char *C, char *CN, ue_x509_certificate **certificate, ue_private_key **private_key) {

	X509 *certificate_impl;
	EVP_PKEY *private_key_impl;
	RSA *rsa;

	certificate_impl = NULL;
	private_key_impl = NULL;
	rsa = NULL;

	generate_signed_key_pair(ue_x509_certificate_get_impl(ca_certificate), ue_private_key_get_impl(ca_private_key), C, CN, &certificate_impl, &private_key_impl);

	*certificate = ue_x509_certificate_create_empty();
	ue_x509_certificate_set_impl(*certificate, certificate_impl);

	rsa = EVP_PKEY_get1_RSA(private_key_impl);
	*private_key = ue_private_key_create(RSA_PRIVATE_KEY, rsa, RSA_size(rsa));
	EVP_PKEY_free(private_key_impl);

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

static int generate_key_csr(EVP_PKEY **key, char *C, char *CN, X509_REQ **req) {
	*key = EVP_PKEY_new();
	if (!*key) goto err;
	*req = X509_REQ_new();
	if (!*req) goto err;

    RSA *rsa;

    rsa = ue_rsa_keypair_gen(2048);
	if (!EVP_PKEY_assign_RSA(*key, rsa)) goto err;

	X509_REQ_set_pubkey(*req, *key);

	/* Set the DN of the request. */
	X509_NAME *name = X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)C, strlen(C), -1, 0);
	/*X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)REQ_DN_ST, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)REQ_DN_L, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)REQ_DN_O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)REQ_DN_OU, -1, -1, 0);*/
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)CN, strlen(CN), -1, 0);

	/* Self-sign the request to prove that we posses the key. */
	if (!X509_REQ_sign(*req, *key, EVP_sha256())) goto err;
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	return 0;
}



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

static int generate_signed_key_pair(X509 *ca_crt, EVP_PKEY *ca_key, char *C, char *CN, X509 **crt, EVP_PKEY **key) {
	/* Generate the private key and corresponding CSR. */
	X509_REQ *req = NULL;
	if (!generate_key_csr(key, C,CN, &req)) {
		fprintf(stderr, "Failed to generate key and/or CSR!\n");
		return 0;
	}

	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt) goto err;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!generate_set_random_serial(*crt)) goto err;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), (long)2*365*3600);

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto err;

	X509_REQ_free(req);
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(req);
	X509_free(*crt);
	return 0;
}
