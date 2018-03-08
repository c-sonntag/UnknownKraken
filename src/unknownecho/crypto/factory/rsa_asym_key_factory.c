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

#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/alloc.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

static RSA *ue_rsa_keypair_gen(int bits) {
	RSA *ue_rsa_key_pair;
	unsigned long e;
	int ret;
	BIGNUM *bne;
    char *error_buffer;

	ue_rsa_key_pair = NULL;
	bne = NULL;
    e = RSA_F4;
    error_buffer = NULL;

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

static bool ue_rsa_get_string_from_keypair(RSA *keypair, char **pub_key, char **priv_key, size_t *pub_key_length, size_t *priv_key_length) {
	bool succeed;
	size_t priv_key_length_tmp, pub_key_length_tmp;
	BIO *priv, *pub;
	char *pub_key_tmp, *priv_key_tmp, *error_buffer;

	succeed = false;
	priv = NULL;
	pub = NULL;
	pub_key_tmp = NULL;
	priv_key_tmp = NULL;
    error_buffer = NULL;

	if (!(priv = BIO_new(BIO_s_mem()))) {
        ue_openssl_error_handling(error_buffer, "BIO_new private key");
        goto clean_up;
    }

    if (!(pub = BIO_new(BIO_s_mem()))) {
        ue_openssl_error_handling(error_buffer, "BIO_new public key");
        goto clean_up;
    }

    if (!(PEM_write_bio_RSAPrivateKey(priv, keypair, NULL, NULL, 0, NULL, NULL))) {
        ue_openssl_error_handling(error_buffer, "PEM_write_bio_RSAPrivateKey");
        goto clean_up;
    }

    if (!(PEM_write_bio_RSAPublicKey(pub, keypair))) {
        ue_openssl_error_handling(error_buffer, "PEM_write_bio_RSAPublicKey");
        goto clean_up;
    }

    priv_key_length_tmp = BIO_pending(priv);
    pub_key_length_tmp = BIO_pending(pub);

    ue_safe_alloc(priv_key_tmp, char, priv_key_length_tmp + 1);
    ue_safe_alloc(pub_key_tmp, char, pub_key_length_tmp + 1);

    if (BIO_read(priv, priv_key_tmp, priv_key_length_tmp) < 0) {
        ue_openssl_error_handling(error_buffer, "BIO_read private key");
        goto clean_up;
    }

    if (BIO_read(pub, pub_key_tmp, pub_key_length_tmp) < 0) {
        ue_openssl_error_handling(error_buffer, "BIO_read public key");
        goto clean_up;
    }

    priv_key_tmp[priv_key_length_tmp] = '\0';
    pub_key_tmp[pub_key_length_tmp] = '\0';

    *priv_key = priv_key_tmp;
    *pub_key = pub_key_tmp;
    *pub_key_length = pub_key_length_tmp;
    *priv_key_length = priv_key_length_tmp;

	succeed = true;

clean_up:
    BIO_free_all(pub);
    BIO_free_all(priv);
    return succeed;
}

static bool ue_rsa_get_pub_key_from_file(const char *file_name, RSA **pub_key) {
    FILE *fd;
    char *error_buffer;

    fd = NULL;
    error_buffer = NULL;

    if (!(fd = fopen(file_name, "rb"))) {
		ue_stacktrace_push_errno();
		return false;
	}

    *pub_key = RSA_new();

    if (!(*pub_key = PEM_read_RSA_PUBKEY(fd, pub_key, NULL, NULL))) {
		RSA_free(*pub_key);
		fclose(fd);
        ue_openssl_error_handling(error_buffer, "PEM_read_RSA_PUBKEY");
        return false;
    }

    fclose(fd);
    return true;
}

static bool ue_rsa_get_priv_key_from_file(const char *file_name, RSA **priv_key) {
    FILE *fd;
    char *error_buffer;

    fd = NULL;
    error_buffer = NULL;

    if (!(fd = fopen(file_name, "rb"))) {
		ue_stacktrace_push_errno();
		return false;
	}

    *priv_key = RSA_new();

    if (!(*priv_key = PEM_read_RSAPrivateKey(fd, priv_key, NULL, NULL))) {
		RSA_free(*priv_key);
		fclose(fd);
        ue_openssl_error_handling(error_buffer, "PEM_read_RSAPrivateKey");
        return false;
    }

    fclose(fd);
    return true;
}

ue_asym_key *ue_rsa_asym_key_create(int bits) {
	ue_asym_key *akey;
	RSA *ue_rsa_key_pair, *ue_rsa_pk, *ue_rsa_sk;
	BIO *ue_rsa_pk_bio, *ue_rsa_sk_bio;
	char *pub_key_buf, *priv_key_buf;
	size_t pub_key_buf_length, priv_key_buf_length;
	ue_private_key *sk;
	ue_public_key *pk;

	akey = NULL;
	ue_rsa_key_pair = NULL;
	ue_rsa_pk = NULL;
	ue_rsa_sk = NULL;
	ue_rsa_pk_bio = NULL;
	ue_rsa_sk_bio = NULL;
	pub_key_buf = NULL;
	priv_key_buf = NULL;
	sk = NULL;
	pk = NULL;

	if (!(ue_rsa_key_pair = ue_rsa_keypair_gen(bits))) {
		ue_stacktrace_push_msg("Failed to gen openssl RSA keypair");
		goto clean_up;
	}

    if (!(ue_rsa_get_string_from_keypair(ue_rsa_key_pair, &pub_key_buf, &priv_key_buf, &pub_key_buf_length, &priv_key_buf_length))) {
		ue_stacktrace_push_msg("Failed to get string from openssl RSA keypair");
		goto clean_up;
	}

	if (!(ue_rsa_pk_bio = BIO_new_mem_buf(pub_key_buf, pub_key_buf_length))) {
		ue_stacktrace_push_msg("Failed to init new mem BIO for pub key buf");
		goto clean_up;
	}

	if (!(ue_rsa_pk = PEM_read_bio_RSAPublicKey(ue_rsa_pk_bio, NULL, NULL, NULL))) {
		ue_stacktrace_push_msg("Failed to build openssl rsa pk from string");
		goto clean_up;
	}

	if (!(pk = ue_public_key_create(RSA_PUBLIC_KEY, (void *)ue_rsa_pk, bits))) {
		ue_stacktrace_push_msg("Failed to create new rsa public key");
		goto clean_up;
	}

	if (!(ue_rsa_sk_bio = BIO_new_mem_buf(priv_key_buf, priv_key_buf_length))) {
		ue_stacktrace_push_msg("Failed to init new mem BIO for priv key buf");
		goto clean_up;
	}

	if (!(ue_rsa_sk = PEM_read_bio_RSAPrivateKey(ue_rsa_sk_bio, NULL, NULL, NULL))) {
		ue_stacktrace_push_msg("Failed to build openssl rsa sk from string");
		goto clean_up;
	}

	if (!(sk = ue_private_key_create(RSA_PRIVATE_KEY, (void *)ue_rsa_sk, bits))) {
		ue_stacktrace_push_msg("Failed to create new rsa private key");
		goto clean_up;
	}

	if (!(akey = ue_asym_key_create(pk, sk))) {
		ue_stacktrace_push_msg("Failed to create asym key");
		goto clean_up;
	}

clean_up:
	ue_safe_free(pub_key_buf);
	ue_safe_free(priv_key_buf);
	BIO_free_all(ue_rsa_pk_bio);
	BIO_free_all(ue_rsa_sk_bio);
	RSA_free(ue_rsa_key_pair);
	RSA_free(ue_rsa_pk);
	RSA_free(ue_rsa_sk);
	return akey;
}

ue_public_key *ue_rsa_public_key_create_pk_from_file(char *file_path) {
	ue_public_key *pk;
	RSA *ue_rsa_pk;

	pk = NULL;
	ue_rsa_pk = NULL;

	if (!(ue_rsa_get_pub_key_from_file(file_path, &ue_rsa_pk))) {
		ue_stacktrace_push_msg("Failed to read openssl rsa public key from file");
		return NULL;
	}

	if (!(pk = ue_public_key_create(RSA_PUBLIC_KEY, (void *)ue_rsa_pk, RSA_size(ue_rsa_pk)))) {
		ue_stacktrace_push_msg("Failed to build public key from openssl rsa public key");
		RSA_free(ue_rsa_pk);
		return NULL;
	}

	return pk;
}

ue_private_key *ue_rsa_private_key_create_sk_from_file(char *file_path) {
	ue_private_key *sk;
	RSA *ue_rsa_sk;

	sk = NULL;
	ue_rsa_sk = NULL;

	if (!(ue_rsa_get_priv_key_from_file(file_path, &ue_rsa_sk))) {
		ue_stacktrace_push_msg("Failed to read openssl rsa private key from file");
		return NULL;
	}

	if (!(sk = ue_private_key_create(RSA_PRIVATE_KEY, (void *)ue_rsa_sk, RSA_size(ue_rsa_sk)))) {
		ue_stacktrace_push_msg("Failed to build private key from openssl rsa private key");
		RSA_free(ue_rsa_sk);
		return NULL;
	}

	return sk;
}

ue_asym_key *ue_rsa_asym_key_create_from_files(char *pk_file_path, char *sk_file_path) {
	ue_asym_key *akey;

	akey = NULL;

	if (!(akey = ue_asym_key_create(ue_rsa_public_key_create_pk_from_file(pk_file_path), ue_rsa_private_key_create_sk_from_file(sk_file_path)))) {
		ue_stacktrace_push_msg("Failed to create asym key");
		return NULL;
	}

	return akey;
}

ue_public_key *ue_rsa_public_key_from_x509_certificate(ue_x509_certificate *certificate) {
	ue_public_key *public_key;
	EVP_PKEY *public_key_impl;
	RSA *rsa;

	public_key = NULL;
	public_key_impl = NULL;
	rsa = NULL;

	ue_check_parameter_or_return(certificate);
	ue_check_parameter_or_return(ue_x509_certificate_get_impl(certificate));

	public_key_impl = X509_get_pubkey(ue_x509_certificate_get_impl(certificate));
	rsa = EVP_PKEY_get1_RSA(public_key_impl);
	EVP_PKEY_free(public_key_impl);

	if (!(public_key = ue_public_key_create(RSA_PUBLIC_KEY, (void *)rsa, RSA_size(rsa)))) {
		RSA_free(rsa);
		ue_stacktrace_push_msg("Failed to build public key from openssl rsa public key");
		return NULL;
	}

	RSA_free(rsa);

	return public_key;
}

ue_private_key *ue_rsa_private_key_from_key_certificate(const char *file_name) {
	BIO *bio;
	ue_private_key *private_key;
	EVP_PKEY *private_key_impl;
	RSA *rsa;

	bio = NULL;
	private_key = NULL;
	private_key_impl = NULL;
	rsa = NULL;

	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, file_name)) {
		goto clean_up;
	}
	private_key_impl = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!private_key_impl) {
		goto clean_up;
	}

	rsa = EVP_PKEY_get1_RSA(private_key_impl);

	if (!(private_key = ue_private_key_create(RSA_PRIVATE_KEY, (void *)rsa, RSA_size(rsa)))) {
		ue_stacktrace_push_msg("Failed to build RSA private key from key certificate file");
		goto clean_up;
	}

clean_up:
	EVP_PKEY_free(private_key_impl);
	RSA_free(rsa);
	BIO_free_all(bio);
	return private_key;
}
