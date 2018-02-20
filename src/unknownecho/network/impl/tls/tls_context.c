#include <unknownecho/network/api/tls/tls_context.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/errorHandling/logger.h>

#include <openssl/ssl.h>
#include <string.h>

struct ue_tls_context {
	SSL_CTX *impl;
};

static char *local_passphrase = NULL;

static int password_callback(char *buf, int num, int rwflag, void *userdata) {
	if (!local_passphrase) {
		ue_logger_warn("Passphrase callback is called to decipher certificate, but no passphrase is provide");
		return -1;
	}

    if (num < strlen(local_passphrase) + 1) {
        return 0;
    }

    strcpy(buf, local_passphrase);
    return strlen(local_passphrase);
}

ue_tls_context *ue_tls_context_create(ue_tls_method *method) {
	ue_tls_context *context;
	char *error_buffer;

	ue_safe_alloc(context, ue_tls_context, 1);
	if (!(context->impl = SSL_CTX_new(ue_tls_method_get_impl(method)))) {
		ue_openssl_error_handling(error_buffer, "SSL_CTX_new");
		ue_safe_free(context);
		return NULL;
	}

	return context;
}

void ue_tls_context_destroy(ue_tls_context *context) {
	if (context) {
		SSL_CTX_free(context->impl);
		ue_safe_free(context);
	}
}

bool ue_tls_context_load_certificates(ue_tls_context *context, ue_pkcs12_keystore *keystore) {
	char *error_buffer;

    error_buffer = NULL;

	if (SSL_CTX_use_certificate(context->impl, ue_x509_certificate_get_impl(keystore->certificate)) <= 0) {
        ue_openssl_error_handling(error_buffer, "Load keystore certificate into to context");
        return false;
    }

	if (SSL_CTX_use_PrivateKey(context->impl, ue_private_key_get_impl(keystore->private_key)) <= 0) {
		ue_openssl_error_handling(error_buffer, "Load keystore private key into context");
        return false;
	}

	if (SSL_CTX_check_private_key(context->impl) != 1) {
        ue_openssl_error_handling(error_buffer, "Private key and certificate are not matching");
        return false;
    }

	/*if (ca_pk_path) {
        if (!SSL_CTX_load_verify_locations(context->impl, ca_pk_path, NULL)) {
            ue_openssl_error_handling(error_buffer, "verify locations of RSA CA certificate file");
            return false;
        }

        SSL_CTX_set_verify(context->impl, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(context->impl, 1);
    }*/

	return true;
}

bool ue_tls_context_load_certificates_from_path(ue_tls_context *context, char *passphrase, char *ca_pk_path, char *pk_path, char *sk_path) {
	char *error_buffer;

    error_buffer = NULL;
    local_passphrase = passphrase;

    SSL_CTX_set_default_passwd_cb(context->impl, password_callback);
    if (SSL_CTX_use_certificate_file(context->impl, pk_path, SSL_FILETYPE_PEM) <= 0) {
        ue_openssl_error_handling(error_buffer, "get server certificate");
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(context->impl, sk_path, SSL_FILETYPE_PEM) <= 0) {
        ue_openssl_error_handling(error_buffer, "get server private key");
        return false;
    }

    if (SSL_CTX_check_private_key(context->impl) != 1) {
        ue_openssl_error_handling(error_buffer, "Private key and certificate are not matching");
        return false;
    }

    if (ca_pk_path) {
        if (!SSL_CTX_load_verify_locations(context->impl, ca_pk_path, NULL)) {
            ue_openssl_error_handling(error_buffer, "verify locations of RSA CA certificate file");
            return false;
        }

        SSL_CTX_set_verify(context->impl, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(context->impl, 1);
    }

    return true;
}

const void *ue_tls_context_get_impl(ue_tls_context *context) {
	return context->impl;
}
