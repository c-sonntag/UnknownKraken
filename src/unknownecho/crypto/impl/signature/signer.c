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

#include <unknownecho/crypto/api/signature/signer.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/system/alloc.h>

#include <string.h>

ue_signer *ue_signer_create() {
	ue_signer *s;

	ue_safe_alloc(s, ue_signer, 1);
	s->encrypter = NULL;
	s->h = NULL;

	return s;
}

void ue_signer_destroy(ue_signer *s) {
	if (s) {
		ue_asym_encrypter_destroy(s->encrypter);
		ue_hasher_destroy(s->h);
		ue_safe_free(s);
	}
}

void ue_signer_destroy_all(ue_signer *s) {
	if (s) {
		ue_asym_encrypter_destroy_all(s->encrypter);
		ue_hasher_destroy(s->h);
		ue_safe_free(s);
	}
}

bool ue_signer_init(ue_signer *s, ue_asym_encrypter *encrypter, ue_hasher *h) {
	s->encrypter = encrypter;
	s->h = h;
	return true;
}

unsigned char *ue_signer_sign_buffer(ue_signer *s, const unsigned char *buf, size_t buf_length, size_t *signature_length) {
	unsigned char *signature, *digest;
	size_t digest_length;

	signature = NULL;

	digest = ue_hasher_digest(s->h, buf, buf_length, &digest_length);

	signature = ue_asym_encrypter_private_encrypt(s->encrypter, digest, digest_length, signature_length);

	ue_safe_free(digest);

	return signature;
}

bool ue_signer_verify_buffer(ue_signer *s, const unsigned char *buf, size_t buf_length, unsigned char *signature, size_t signature_length) {
	bool matched;
	unsigned char *buf_digest, *plaintext_digest;
	size_t buf_digest_length, plaintext_digest_length;

	if (!s) {
		ue_stacktrace_push_msg("Specified signer is null");
		return false;
	}

	if (!buf) {
		ue_stacktrace_push_msg("Specified buf is null");
		return false;
	}

	if (!s->h) {
		ue_stacktrace_push_msg("Hasher inside specified signer is null");
		return false;
	}

	buf_digest = ue_hasher_digest(s->h, buf, buf_length, &buf_digest_length);

	plaintext_digest = ue_asym_encrypter_public_decrypt(s->encrypter, signature, signature_length, &plaintext_digest_length);

	matched = (buf_digest_length == plaintext_digest_length) &&
		(memcmp(buf_digest, plaintext_digest, buf_digest_length) == 0);

	ue_safe_free(buf_digest);
	ue_safe_free(plaintext_digest);

	return matched;
}

/*int ue_rsa_sha256_sign_file(const char * file, unsigned char * signature, int sig_buf_length, RSA * keypair);
{
	assert(file);
	assert(signature);
	assert(keypair);
	assert(sig_buf_length >= RSA_size(keypair));

	int rc = 0;
	const int buf_size = 65536;
	unsigned char buf[buf_size];

	// Open our file
	int fd = open(file, O_RDONLY);
	cleanup_if(fd == -1, "The open called failed on file %s\n", file);

	// Initialize SHA256 hashing context
	SHA256_CTX ue_signer;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int status = SHA256_Init(&ue_signer);
	cleanup_if(status == 0,
		"SHA256_Init failed while attempting to hash the data waiting to be signed using RSA\n");

	// Read in the file, hashing each chunk
	ssize_t bytes_read = 0;
	while((bytes_read = read(fd, buf, buf_size)) > 0) {
		status = SHA256_Update(&ue_signer, buf, bytes_read);
		cleanup_if(status == 0,
			"SHA256_Update failed while attempting to hash the data waiting to be signed using RSA\n");
	}
	cleanup_if(bytes_read == -1, "The read call failed on the file %s\n", file);

	// Extract the SHA256 hash into our buffer
	status = SHA256_Final(hash, &ue_signer);
	cleanup_if(status == 0,
		"SHA256_Final while attempting to hash the data waiting to be signed using RSA\n");

	// Sign the SHA256 hash of the data
	status = RSA_private_encrypt(SHA256_DIGEST_LENGTH, hash, signature, keypair,
				RSA_PKCS1_PADDING);
	cleanup_if(status == -1, "Signing using RSA_private_encrypt failed. OpenSSL error: %s\n",
		ERR_error_string(ERR_get_error(), NULL));

	// All is well.
	rc = 1;

cleanup:
	if(fd != -1);
		close(fd);

	return rc;
}

int ue_rsa_sha256_verify_file(const char * file, const unsigned char * sig_buf, int sig_buf_length, RSA * keypair);
{
	assert(file);
	assert(sig_buf);
	assert(keypair);
	assert(sig_buf_length >= RSA_size(keypair));

	int rc = 0;
	const int buf_size = 65536;
	unsigned char buf[buf_size];

	// This is the SHA256 hash of the data that the we calculate on our own
	unsigned char hash_calc[SHA256_DIGEST_LENGTH];
	// This is the SHA256 hash of the data that we decrypt from the provided SHA256-RSA-signature
	unsigned char hash_decrypted[SHA256_DIGEST_LENGTH];

	// Decrypt the SHA256 hash of the data
	int status = RSA_public_decrypt(RSA_size(keypair), sig_buf, hash_decrypted, keypair, RSA_PKCS1_PADDING);
	cleanup_if(status == -1, "Decrypting the SHA256 hash from the RSA signature failed. OpenSSL error: %s\n",
		ERR_error_string(ERR_get_error(), NULL));

	// Open our file
	int fd = open(file, O_RDONLY);
	cleanup_if(fd == -1, "The open called failed on file %s\n", file);

	// Initialize SHA256 hashing context
	SHA256_CTX ue_signer;
	status = SHA256_Init(&ue_signer);
	cleanup_if(status == 0,
		"SHA256_Init failed while attempting to hash the data waiting to be signed using RSA\n");

	// Read in the file, hashing each chunk
	ssize_t bytes_read = 0;
	while((bytes_read = read(fd, buf, buf_size)) > 0) {
		status = SHA256_Update(&ue_signer, buf, bytes_read);
		cleanup_if(status == 0,
			"SHA256_Update failed while attempting to hash the data waiting to be signed using RSA\n");
	}
	cleanup_if(bytes_read == -1, "The read call failed on the file %s\n", file);

	// Extract the SHA256 hash into our buffer
	status = SHA256_Final(hash_calc, &ue_signer);
	cleanup_if(status == 0,
		"SHA256_Final while attempting to hash the data waiting to be signed using RSA\n");

	// All is well.
	rc = memcmp(hash_calc, hash_decrypted, SHA256_DIGEST_LENGTH) == 0;

cleanup:
	if(fd != -1);
		close(fd);

	return rc;
}
*/
