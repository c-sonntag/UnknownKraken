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

#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/fileSystem/file_utility.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/string/string_utility.h>

#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>

#include <string.h>


static bool load_certs_keys_p12(ue_pkcs12_keystore *keystore, const PKCS12 *p12, const char *passphrase,
    int passphrase_len, const EVP_CIPHER *enc);

static bool load_certs_pkeys_bags(ue_pkcs12_keystore *keystore, const STACK_OF(PKCS12_SAFEBAG) *bags,
    const char *passphrase, int passphrase_len, const EVP_CIPHER *enc);

static bool load_certs_pkeys_bag(ue_pkcs12_keystore *keystore, const PKCS12_SAFEBAG *bag, const char *passphrase,
    int passphrase_len, const EVP_CIPHER *enc);


typedef struct pw_cb_data {
    const void *password;
    const char *prompt_info;
} PW_CB_DATA;


static ue_pkcs12_keystore *ue_pkcs12_keystore_create_empty() {
    ue_pkcs12_keystore *keystore;

    ue_safe_alloc(keystore, ue_pkcs12_keystore, 1)
    keystore->certificate = NULL;
    keystore->private_key = NULL;
    keystore->friendly_name = NULL;
    keystore->other_certificates = NULL;
    keystore->other_certificates_number = 0;

    return keystore;
}

ue_pkcs12_keystore *ue_pkcs12_keystore_create(ue_x509_certificate *certificate, ue_private_key *private_key, char *friendly_name) {
    ue_pkcs12_keystore *keystore;

    ue_safe_alloc(keystore, ue_pkcs12_keystore, 1)
    keystore->certificate = certificate;
    keystore->private_key = private_key;
    keystore->friendly_name = ue_string_create_from(friendly_name);
    keystore->other_certificates = NULL;
    keystore->other_certificates_number = 0;

    return keystore;
}

ue_pkcs12_keystore *ue_pkcs12_keystore_load(const char *file_name, char *passphrase) {
    ue_pkcs12_keystore *keystore;
    BIO *bio;
    char *error_buffer;
    PKCS12 *p12;

    keystore = NULL;
    bio = NULL;
    error_buffer = NULL;
    p12 = NULL;

    if (!ue_is_file_exists(file_name)) {
        ue_stacktrace_push_msg("Specified keystore file '%s' doesn't exists", file_name);
        return NULL;
    }

    if (!(bio = BIO_new_file(file_name, "rb"))) {
        ue_openssl_error_handling(error_buffer, "BIO_new_file");
        goto clean_up;
    }

    if (!(p12 = d2i_PKCS12_bio(bio, NULL))) {
        ue_openssl_error_handling(error_buffer, "d2i_PKCS12_bio");
        goto clean_up;
    }

    keystore = ue_pkcs12_keystore_create_empty();

    if (!load_certs_keys_p12(keystore, p12, passphrase, (int)strlen(passphrase), EVP_des_ede3_cbc())) {
        ue_pkcs12_keystore_destroy(keystore);
        keystore = NULL;
        ue_stacktrace_push_msg("Failed to load certs from keystore '%s'", file_name);
    }

clean_up:
    BIO_free(bio);
    ue_safe_free(error_buffer);
    PKCS12_free(p12);
    return keystore;
}

void ue_pkcs12_keystore_destroy(ue_pkcs12_keystore *keystore) {
    int i;

    if (keystore) {
        ue_x509_certificate_destroy(keystore->certificate);
        ue_private_key_destroy(keystore->private_key);
        if (keystore->other_certificates) {
            for (i = 0; i < keystore->other_certificates_number; i++) {
                ue_x509_certificate_destroy(keystore->other_certificates[i]);
            }
            ue_safe_free(keystore->other_certificates);
        }
        ue_safe_free(keystore->friendly_name);
        ue_safe_free(keystore);
    }
}

bool ue_pkcs12_keystore_add_certificate(ue_pkcs12_keystore *keystore, ue_x509_certificate *certificate, const unsigned char *friendly_name, size_t friendly_name_size) {
    bool result;

    result = false;

    ue_check_parameter_or_return(keystore);
    ue_check_parameter_or_return(certificate);
    ue_check_parameter_or_return(ue_x509_certificate_get_impl(certificate));
    ue_check_parameter_or_return(friendly_name);
    ue_check_parameter_or_return(friendly_name_size > 0);

    if (keystore->other_certificates) {
        ue_safe_realloc(keystore->other_certificates, ue_x509_certificate *, keystore->other_certificates_number, 1);
    } else {
        ue_safe_alloc(keystore->other_certificates, ue_x509_certificate *, 1);
    }
    keystore->other_certificates[keystore->other_certificates_number] = certificate;
    X509_alias_set1(ue_x509_certificate_get_impl(certificate), friendly_name, friendly_name_size);
    keystore->other_certificates_number++;

    result = true;

    return result;
}

bool ue_pkcs12_keystore_add_certificate_from_file(ue_pkcs12_keystore *keystore, const char *file_name, const unsigned char *friendly_name, size_t friendly_name_size) {
    ue_x509_certificate *certificate;

    if (!ue_x509_certificate_load_from_file(file_name, &certificate)) {
		ue_stacktrace_push_msg("Failed to load certificate from path '%s'", file_name);
		return false;
	}

    if (!ue_pkcs12_keystore_add_certificate(keystore, certificate, friendly_name, friendly_name_size)) {
        ue_x509_certificate_destroy(certificate);
        ue_stacktrace_push_msg("Failed to add loaded certificate");
        return false;
    }

    return true;
}

bool ue_pkcs12_keystore_add_certificate_from_bytes(ue_pkcs12_keystore *keystore, unsigned char *data, size_t data_size, const unsigned char *friendly_name,
    size_t friendly_name_size) {

    ue_x509_certificate *certificate;

    if (!(certificate = ue_x509_certificate_load_from_bytes(data, data_size))) {
        ue_stacktrace_push_msg("Failed to create x509 certificate from this data");
        return false;
    }

    if (!ue_pkcs12_keystore_add_certificate(keystore, certificate, friendly_name, friendly_name_size)) {
        ue_x509_certificate_destroy(certificate);
        ue_stacktrace_push_msg("Failed to add loaded certificate");
        return false;
    }

    return true;
}

bool ue_pkcs12_keystore_add_certificates_bundle(ue_pkcs12_keystore *keystore, const char *file_name, const char *passphrase) {
    int i;
    BIO *bio;
    STACK_OF(X509_INFO) *xis;
    X509_INFO *xi;
    PW_CB_DATA cb_data;
    bool result;
    ue_x509_certificate *new_certificate;
    char *error_buffer;

    cb_data.password = passphrase;
    cb_data.prompt_info = file_name;
    result = false;
    error_buffer = NULL;
    xis = NULL;
    bio = NULL;

    if (!(bio = BIO_new_file(file_name, "rb"))) {
        ue_openssl_error_handling(error_buffer, "BIO_new_file");
        return false;
    }

    if (!(xis = PEM_X509_INFO_read_bio(bio, NULL, NULL, &cb_data))) {
        ue_openssl_error_handling(error_buffer, "PEM_X509_INFO_read_bio");
        goto clean_up;
    }

    if (keystore->other_certificates) {
        ue_safe_realloc(keystore->other_certificates, ue_x509_certificate *, keystore->other_certificates_number, sk_X509_INFO_num(xis));
    } else {
        ue_safe_alloc(keystore->other_certificates, ue_x509_certificate *, sk_X509_INFO_num(xis));
    }

    for (i = 0; i < sk_X509_INFO_num(xis); i++) {
        xi = sk_X509_INFO_value(xis, i);
        new_certificate = ue_x509_certificate_create_empty();
        ue_x509_certificate_set_impl(new_certificate, X509_dup(xi->x509));
        keystore->other_certificates[keystore->other_certificates_number] = new_certificate;
        keystore->other_certificates_number++;
    }

    result = true;

clean_up:
    ue_safe_free(error_buffer);
    BIO_free(bio);
    sk_X509_INFO_pop_free(xis, X509_INFO_free);
    return result;
}

bool ue_pkcs12_keystore_remove_certificate(ue_pkcs12_keystore *keystore, const unsigned char *friendly_name, size_t friendly_name_size) {
    bool result;
    size_t i;
    unsigned char *alias;
    int alias_size;

    result = false;

    for (i = 0; i < keystore->other_certificates_number; i++) {
        if (!keystore->other_certificates[i]) {
            continue;
        }

        if (!(alias = X509_alias_get0(ue_x509_certificate_get_impl(keystore->other_certificates[i]), &alias_size))) {
            ue_logger_warn("Other certificates '%d' in keystore have no alias", i);
            continue;
        }

        if ((size_t)alias_size == friendly_name_size && memcmp(alias, friendly_name, friendly_name_size) == 0) {
            ue_x509_certificate_destroy(keystore->other_certificates[i]);
            keystore->other_certificates[i] = NULL;
            break;
        }
    }

    result = true;

    return result;
}

ue_x509_certificate *ue_pkcs12_keystore_find_certificate_by_friendly_name(ue_pkcs12_keystore *keystore, const unsigned char *friendly_name, size_t friendly_name_size) {
    size_t i;
    unsigned char *alias;
    int alias_size;

    ue_check_parameter_or_return(keystore);
    ue_check_parameter_or_return(friendly_name);
    ue_check_parameter_or_return(friendly_name_size > 0);

    for (i = 0; i < keystore->other_certificates_number; i++) {
        if (!keystore->other_certificates[i]) {
            continue;
        }

        if (!(alias = X509_alias_get0(ue_x509_certificate_get_impl(keystore->other_certificates[i]), &alias_size))) {
            ue_logger_warn("Other certificates '%d' in keystore have no alias", i);
            continue;
        }

        if ((size_t)alias_size == friendly_name_size && memcmp(alias, friendly_name, friendly_name_size) == 0) {
            return keystore->other_certificates[i];
        }
    }

    return NULL;
}

bool ue_pkcs12_keystore_write(ue_pkcs12_keystore *keystore, const char *file_name, char *passphrase) {
    bool result;
    STACK_OF(X509) *other_certificates;
    int i;
    char *error_buffer;
    PKCS12 *p12;
    FILE *fd;

    result = false;
    other_certificates = sk_X509_new_null();
    error_buffer = NULL;
    p12 = NULL;
    fd = NULL;

    ue_check_parameter_or_return(keystore);

    for (i = 0; i < keystore->other_certificates_number; i++) {
        if (keystore->other_certificates[i] && !sk_X509_push(other_certificates, ue_x509_certificate_get_impl(keystore->other_certificates[i]))) {
            ue_openssl_error_handling(error_buffer, "Failed to push other_certificates[%d] into STACK_OF(X509)");
            goto clean_up;
        }
    }

    if (!(p12 = PKCS12_create(passphrase, keystore->friendly_name, ue_private_key_get_impl(keystore->private_key),
        ue_x509_certificate_get_impl(keystore->certificate), other_certificates, 0, 0, 0, 0, 0))) {

        ue_openssl_error_handling(error_buffer, "PKCS12_create");
        goto clean_up;
    }

    if (!(fd = fopen(file_name, "wb"))) {
        ue_stacktrace_push_errno();
        goto clean_up;
    }

    if (!i2d_PKCS12_fp(fd, p12)) {
        ue_openssl_error_handling(error_buffer, "i2d_PKCS12_fp");
        goto clean_up;
    }

    result = true;

clean_up:
    ue_safe_fclose(fd);
    PKCS12_free(p12);
    sk_X509_free(other_certificates);
    ue_safe_free(error_buffer);
    return result;
}

static bool load_certs_keys_p12(ue_pkcs12_keystore *keystore, const PKCS12 *p12, const char *passphrase,
    int passphrase_len, const EVP_CIPHER *enc) {

    bool result;
    STACK_OF(PKCS7) *asafes;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    int i, bagnid;
    PKCS7 *p7;
    char *error_buffer;

    result = false;
    asafes = NULL;
    bags = NULL;
    p7 = NULL;
    error_buffer = NULL;

    if (!(asafes = PKCS12_unpack_authsafes(p12))) {
        ue_openssl_error_handling(error_buffer, "PKCS12_unpack_authsafes");
        return false;
    }

    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(p7, passphrase, passphrase_len);
        } else {
            continue;
        }
        if (!bags) {
            goto clean_up;
        }

        if (!load_certs_pkeys_bags(keystore, bags, passphrase, passphrase_len, enc)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            goto clean_up;
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        bags = NULL;
    }

    result = true;

 clean_up:
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    return result;
}

static bool load_certs_pkeys_bags(ue_pkcs12_keystore *keystore, const STACK_OF(PKCS12_SAFEBAG) *bags,
    const char *passphrase, int passphrase_len, const EVP_CIPHER *enc) {

    int i;

    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!load_certs_pkeys_bag(keystore, sk_PKCS12_SAFEBAG_value(bags, i), passphrase, passphrase_len, enc)) {
            ue_logger_trace("Failed to load certs and keys of bag '%d'", i);
            // return false ?;
        }
    }

    return true;
}

static bool load_certs_pkeys_bag(ue_pkcs12_keystore *keystore, const PKCS12_SAFEBAG *bag, const char *passphrase,
    int passphrase_len, const EVP_CIPHER *enc) {

    EVP_PKEY *pkey;
    PKCS8_PRIV_KEY_INFO *p8;
    const PKCS8_PRIV_KEY_INFO *p8c;
    X509 *x509;
    //const STACK_OF(X509_ATTRIBUTE) *attrs;
    char *error_buffer, *name;
    ue_x509_certificate *other_certificate;

    pkey = NULL;
    p8 = NULL;
    x509 = NULL;
    //attrs = PKCS12_SAFEBAG_get0_attrs(bag);
    error_buffer = NULL;

    switch (PKCS12_SAFEBAG_get_nid(bag)) {
        case NID_keyBag:
            p8c = PKCS12_SAFEBAG_get0_p8inf(bag);
            if (!(pkey = EVP_PKCS82PKEY(p8c))) {
                ue_openssl_error_handling(error_buffer, "EVP_PKCS82PKEY");
                return false;
            }

            /* Append private key here */


            EVP_PKEY_free(pkey);
            break;

        case NID_pkcs8ShroudedKeyBag:
            if (!(p8 = PKCS12_decrypt_skey(bag, passphrase, passphrase_len))) {
                ue_openssl_error_handling(error_buffer, "PKCS12_decrypt_skey");
                return false;
            }
            if (!(pkey = EVP_PKCS82PKEY(p8))) {
                ue_openssl_error_handling(error_buffer, "EVP_PKCS82PKEY");
                PKCS8_PRIV_KEY_INFO_free(p8);
                return false;
            }

            PKCS8_PRIV_KEY_INFO_free(p8);
            if (keystore->private_key) {
                ue_logger_warn("Private key already set in the keystore");
            } else {
                keystore->private_key = ue_private_key_create_from_impl(pkey);
            }
            EVP_PKEY_free(pkey);
            break;

        case NID_certBag:
            if (PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)
                return true;
            if ((x509 = PKCS12_SAFEBAG_get1_cert(bag)) == NULL)
                return false;

            name = PKCS12_get_friendlyname((PKCS12_SAFEBAG *)bag);
            if (keystore->friendly_name) {
                if (keystore->other_certificates) {
                    ue_safe_realloc(keystore->other_certificates, ue_x509_certificate *, keystore->other_certificates_number, 1);
                } else {
                    ue_safe_alloc(keystore->other_certificates, ue_x509_certificate *, 1);
                }
                X509_alias_set1(x509, (const unsigned char *)name, strlen(name));
                ue_safe_free(name);
                other_certificate = ue_x509_certificate_create_empty();
                ue_x509_certificate_set_impl(other_certificate, x509);
                keystore->other_certificates[keystore->other_certificates_number] = other_certificate;
                keystore->other_certificates_number++;
            } else {
                keystore->friendly_name = name;
                keystore->certificate = ue_x509_certificate_create_empty();
                ue_x509_certificate_set_impl(keystore->certificate, x509);
            }
            break;

        case NID_safeContentsBag:
            return load_certs_pkeys_bags(keystore, PKCS12_SAFEBAG_get0_safes(bag), passphrase, passphrase_len, enc);

        default:
            ue_logger_warn("Warning unsupported bag type : '%s'", PKCS12_SAFEBAG_get0_type(bag));
            return true;
    }

    return true;
}
