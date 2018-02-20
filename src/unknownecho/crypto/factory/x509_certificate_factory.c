#include <unknownecho/crypto/api/certificate/x509_certificate_parameters.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_generation.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/errorHandling/stacktrace.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include <string.h>


static int generate_key_csr(EVP_PKEY **key, char *C, char *CN, X509_REQ **req);

static int generate_set_random_serial(X509 *crt);

static int generate_signed_key_pair(X509 *ca_crt, EVP_PKEY *ca_key, char *C, char *CN, X509 **crt, EVP_PKEY **key);

static RSA *ue_rsa_keypair_gen(int bits);


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
