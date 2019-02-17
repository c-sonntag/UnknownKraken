/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
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

#include <uk/unknownecho/network/api/tls/tls_context.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/uecm.h>
#include <uk/utils/ei.h>

#include <openssl/ssl.h>

#include <string.h>

struct uk_crypto_tls_context {
    SSL_CTX *impl;
};

static char *local_passphrase = NULL;

static int password_callback(char *buf, int num, int rwflag, void *userdata) {
    if (!local_passphrase) {
        uk_utils_logger_warn("Passphrase callback is called to decipher certificate, but no passphrase is provide");
        return -1;
    }

    if (num < strlen(local_passphrase) + 1) {
        return 0;
    }

    strcpy(buf, local_passphrase);
    return strlen(local_passphrase);
}

uk_crypto_tls_context *uk_crypto_tls_context_create(uk_crypto_tls_method *method) {
    uk_crypto_tls_context *context;
    char *error_buffer;

    context = NULL;

    uk_utils_safe_alloc(context, uk_crypto_tls_context, 1);
    if (!(context->impl = SSL_CTX_new(uk_crypto_tls_method_get_impl(method)))) {
        uk_crypto_openssl_error_handling(error_buffer, "SSL_CTX_new");
        uk_utils_safe_free(context);
        return NULL;
    }

    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    SSL_CTX_set_options(context->impl, flags);

    return context;
}

void uk_crypto_tls_context_destroy(uk_crypto_tls_context *context) {
    if (context) {
        SSL_CTX_free(context->impl);
        uk_utils_safe_free(context);
    }
}

/*typedef struct verify_options_st {
    int depth;
    int quiet;
    int error;
    int return_error;
} VERIFY_CB_ARGS;

VERIFY_CB_ARGS verify_args = { 0, 0, X509_V_OK, 0 };

BIO *bio;

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#include <openssl/bn.h>
#include <openssl/ssl.h>

static void nodes_print(const char *name, STACK_OF(X509_POLICY_NODE) *nodes)
{
    X509_POLICY_NODE *node;
    int i;

    BIO_printf(bio, "%s Policies:", name);
    if (nodes) {
        BIO_puts(bio, "\n");
        for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            X509_POLICY_NODE_print(bio, node, 2);
        }
    } else {
        BIO_puts(bio, " <empty>\n");
    }
}

void policies_print(X509_STORE_CTX *ctx)
{
    X509_POLICY_TREE *tree;
    int explicit_policy;
    tree = X509_STORE_CTX_get0_policy_tree(ctx);
    explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

    BIO_printf(bio, "Require explicit Policy: %s\n",
               explicit_policy ? "True" : "False");

    nodes_print("Authority", X509_policy_tree_get0_policies(tree));
    nodes_print("User", X509_policy_tree_get0_user_policies(tree));
}

int verify_callback(int ok, X509_STORE_CTX *ctx) {
    X509 *err_cert;
    int err, depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    if (!verify_args.quiet || !ok) {
        BIO_printf(bio, "depth=%d ", depth);
        if (err_cert != NULL) {
            X509_NAME_print_ex(bio,
                               X509_get_subject_name(err_cert),
                               0, XN_FLAG_ONELINE);
            BIO_puts(bio, "\n");
        } else {
            BIO_puts(bio, "<no cert>\n");
        }
    }
    if (!ok) {
        BIO_printf(bio, "verify error:num=%d:%s\n", err,
                   X509_verify_cert_error_string(err));
        if (verify_args.depth >= depth) {
            if (!verify_args.return_error)
                ok = 1;
            verify_args.error = err;
        } else {
            ok = 0;
            verify_args.error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        }
    }
    switch (err) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        BIO_puts(bio, "issuer= ");
        X509_NAME_print_ex(bio, X509_get_issuer_name(err_cert),
                           0, XN_FLAG_ONELINE);
        BIO_puts(bio, "\n");
        break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        BIO_printf(bio, "notBefore=");
        ASN1_TIME_print(bio, X509_get0_notBefore(err_cert));
        BIO_printf(bio, "\n");
        break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        BIO_printf(bio, "notAfter=");
        ASN1_TIME_print(bio, X509_get0_notAfter(err_cert));
        BIO_printf(bio, "\n");
        break;
    case X509_V_ERR_NO_EXPLICIT_POLICY:
        if (!verify_args.quiet)
            policies_print(ctx);
        break;
    }
    if (err == X509_V_OK && ok == 2 && !verify_args.quiet)
        policies_print(ctx);
    if (ok && !verify_args.quiet)
        BIO_printf(bio, "verify return:%d\n", ok);
return ok;
}*/

bool uk_crypto_tls_context_load_certificates(uk_crypto_tls_context *context, uk_crypto_pkcs12_keystore *keystore, uk_crypto_x509_certificate **ca_certificates, int ca_certificate_count) {
    char *error_buffer;
    X509_STORE *store;
    int i;

    error_buffer = NULL;
    store = NULL;

    //bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (SSL_CTX_use_certificate(context->impl, uk_crypto_x509_certificate_get_impl(keystore->certificate)) <= 0) {
        uk_crypto_openssl_error_handling(error_buffer, "Load keystore certificate into to context");
        return false;
    }

    if (SSL_CTX_use_PrivateKey(context->impl, uk_crypto_private_key_get_impl(keystore->private_key)) <= 0) {
        uk_crypto_openssl_error_handling(error_buffer, "Load keystore private key into context");
        return false;
    }

    if (SSL_CTX_check_private_key(context->impl) != 1) {
        uk_crypto_openssl_error_handling(error_buffer, "Private key and certificate are not matching");
        return false;
    }

    /*if (ca_certificate) {
        if (!(store = SSL_CTX_get_cert_store(context->impl))) {
            uk_crypto_openssl_error_handling(error_buffer, "Failed to get store of TLS context");
            return false;
        }

        if (!X509_STORE_add_cert(store, uk_crypto_x509_certificate_get_impl(ca_certificate))) {
            uk_crypto_openssl_error_handling(error_buffer, "Failed to add ca certificate to TLS context store");
            return false;
        }

        SSL_CTX_set_verify(context->impl, SSL_VERIFY_PEER, NULL);
        //SSL_CTX_set_verify_depth(context->impl, 1);
    }*/

    if (ca_certificates && ca_certificate_count > 0) {
        if (!(store = SSL_CTX_get_cert_store(context->impl))) {
            uk_crypto_openssl_error_handling(error_buffer, "Failed to get store of TLS context");
            return false;
        }

        for (i = 0; i < ca_certificate_count; i++) {
            if (!X509_STORE_add_cert(store, uk_crypto_x509_certificate_get_impl(ca_certificates[i]))) {
                uk_crypto_openssl_error_handling(error_buffer, "Failed to add ca certificate to TLS context store");
                return false;
            }
        }

        SSL_CTX_set_verify(context->impl, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(context->impl, 1);
    }

    return true;
}

bool uk_crypto_tls_context_load_certificates_from_path(uk_crypto_tls_context *context, char *passphrase, char *ca_pk_path, char *pk_path, char *sk_path) {
    char *error_buffer;

    error_buffer = NULL;
    local_passphrase = passphrase;

    SSL_CTX_set_default_passwd_cb(context->impl, password_callback);
    if (SSL_CTX_use_certificate_file(context->impl, pk_path, SSL_FILETYPE_PEM) <= 0) {
        uk_crypto_openssl_error_handling(error_buffer, "get server certificate");
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(context->impl, sk_path, SSL_FILETYPE_PEM) <= 0) {
        uk_crypto_openssl_error_handling(error_buffer, "get server private key");
        return false;
    }

    if (SSL_CTX_check_private_key(context->impl) != 1) {
        uk_crypto_openssl_error_handling(error_buffer, "Private key and certificate are not matching");
        return false;
    }

    if (ca_pk_path) {
        if (!SSL_CTX_load_verify_locations(context->impl, ca_pk_path, NULL)) {
            uk_crypto_openssl_error_handling(error_buffer, "verify locations of RSA CA certificate file");
            return false;
        }

        SSL_CTX_set_verify(context->impl, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(context->impl, 1);
    }

    return true;
}

const void *uk_crypto_tls_context_get_impl(uk_crypto_tls_context *context) {
    return context->impl;
}
