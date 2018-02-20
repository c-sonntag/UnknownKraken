#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/fileSystem/file_utility.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/string/string_utility.h>

#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>

#include <string.h>


static bool load_certs_keys_p12(ue_pkcs12_keystore *keystore, const PKCS12 *p12, const char *passphrase,
    int passphrase_len, char *pem_passphrase, const EVP_CIPHER *enc);

static bool load_certs_pkeys_bags(ue_pkcs12_keystore *keystore, const STACK_OF(PKCS12_SAFEBAG) *bags,
    const char *passphrase, int passphrase_len, char *pem_passphrase, const EVP_CIPHER *enc);

static bool load_certs_pkeys_bag(ue_pkcs12_keystore *keystore, const PKCS12_SAFEBAG *bag, const char *passphrase,
    int passphrase_len, char *pem_passphrase, const EVP_CIPHER *enc);


static int alg_print(const X509_ALGOR *alg);


#define PW_MIN_LENGTH 4
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

ue_pkcs12_keystore *ue_pkcs12_keystore_load(const char *file_name, char *passphrase, char *pem_passphrase) {
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

    if (!load_certs_keys_p12(keystore, p12, passphrase, (int)strlen(passphrase), pem_passphrase, EVP_des_ede3_cbc())) {
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

bool ue_pkcs12_keystore_add_certificate(ue_pkcs12_keystore *keystore, ue_x509_certificate *certificate) {
    bool result;

    result = false;

    if (keystore->other_certificates) {
        ue_safe_realloc(keystore->other_certificates, ue_x509_certificate *, keystore->other_certificates_number, 1);
    } else {
        ue_safe_alloc(keystore->other_certificates, ue_x509_certificate *, 1);
    }
    keystore->other_certificates[keystore->other_certificates_number] = certificate;
    keystore->other_certificates_number++;

    result = true;

    return result;
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

bool ue_pkcs12_keystore_remove_certificate_from_CN(ue_pkcs12_keystore *keystore, const char *file_name) {
    bool result;

    result = false;

    result = true;

    return result;
}

bool ue_pkcs12_keystore_write(ue_pkcs12_keystore *keystore, const char *file_name, char *passphrase, char *pem_passphrase) {
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

    for (i = 0; i < keystore->other_certificates_number; i++) {
        if (!sk_X509_push(other_certificates, ue_x509_certificate_get_impl(keystore->other_certificates[i]))) {
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
    int passphrase_len, char *pem_passphrase, const EVP_CIPHER *enc) {

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
            ue_logger_trace("NID_pkcs7_data");
            bags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            ue_logger_trace("PKCS7 Encrypted data :");
            alg_print(p7->d.encrypted->enc_data->algorithm);
            bags = PKCS12_unpack_p7encdata(p7, passphrase, passphrase_len);
        } else {
            continue;
        }
        if (!bags) {
            goto clean_up;
        }

        if (!load_certs_pkeys_bags(keystore, bags, passphrase, passphrase_len, pem_passphrase, enc)) {
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
    const char *passphrase, int passphrase_len, char *pem_passphrase, const EVP_CIPHER *enc) {

    int i;

    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!load_certs_pkeys_bag(keystore, sk_PKCS12_SAFEBAG_value(bags, i), passphrase, passphrase_len, pem_passphrase, enc)) {
            ue_logger_trace("Failed to load certs and keys of bag '%d'", i);
            // return false ?;
        }
    }

    return true;
}

static bool load_certs_pkeys_bag(ue_pkcs12_keystore *keystore, const PKCS12_SAFEBAG *bag, const char *passphrase,
    int passphrase_len, char *pem_passphrase, const EVP_CIPHER *enc) {

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
            ue_logger_trace("NID_keyBag");
            //print_attribs(out, attrs, "Bag Attributes");
            p8c = PKCS12_SAFEBAG_get0_p8inf(bag);
            if (!(pkey = EVP_PKCS82PKEY(p8c))) {
                ue_openssl_error_handling(error_buffer, "EVP_PKCS82PKEY");
                return false;
            }

            /* Append private key here */

            //print_attribs(out, PKCS8_pkey_get0_attrs(p8c), "Key Attributes");
            /*if (!PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass)) {
                ue_openssl_error_handling(error_buffer, "PEM_write_bio_PrivateKey");
            }*/
            EVP_PKEY_free(pkey);
            break;

        case NID_pkcs8ShroudedKeyBag:
            ue_logger_trace("NID_pkcs8ShroudedKeyBag");
            // log this
            /*if (options & INFO) {
                const X509_SIG *tp8;
                const X509_ALGOR *tp8alg;

                BIO_printf(bio_err, "Shrouded Keybag: ");
                tp8 = PKCS12_SAFEBAG_get0_pkcs8(bag);
                X509_SIG_get0(tp8, &tp8alg, NULL);
                alg_print(tp8alg);
            }*/

            // log
            //print_attribs(out, attrs, "Bag Attributes");
            if (!(p8 = PKCS12_decrypt_skey(bag, passphrase, passphrase_len))) {
                ue_openssl_error_handling(error_buffer, "PKCS12_decrypt_skey");
                return false;
            }
            if (!(pkey = EVP_PKCS82PKEY(p8))) {
                ue_openssl_error_handling(error_buffer, "EVP_PKCS82PKEY");
                PKCS8_PRIV_KEY_INFO_free(p8);
                return false;
            }
            // log
            //print_attribs(out, PKCS8_pkey_get0_attrs(p8), "Key Attributes");

            // append
            /*ret = PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);*/
            PKCS8_PRIV_KEY_INFO_free(p8);
            if (keystore->private_key) {
                ue_logger_warn("Private key already set in the keystore");
            } else {
                keystore->private_key = ue_private_key_create_from_impl(pkey);
            }
            EVP_PKEY_free(pkey);
            break;

        case NID_certBag:
            ue_logger_trace("NID_certBag");

            // log
            //if (options & INFO)
                //BIO_printf(bio_err, "Certificate bag\n");

            if (PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)) {
                //if (options & CACERTS)
                    //return true;
            }/* else if (options & CLCERTS)
                return true;*/
            //print_attribs(out, attrs, "Bag Attributes");
            if (PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)
                return true;
            if ((x509 = PKCS12_SAFEBAG_get1_cert(bag)) == NULL)
                return false;
            //dump_cert_text(out, x509);
            //ret = PEM_write_bio_X509(out, x509);
            //ue_logger_trace("Subject : %s", X509_get_subject_name(x509));
            //ue_logger_trace("Issuer : %s", X509_get_issuer_name(x509));
            //ue_logger_trace(" ");
            name = PKCS12_get_friendlyname((PKCS12_SAFEBAG *)bag);
            if (name) {
                ue_logger_trace("Friendly name : '%s'", name);
                if (keystore->friendly_name) {
                    ue_logger_warn("Friendly name of root certificate already exists in keystore object");
                    ue_safe_free(name);
                } else {
                    keystore->friendly_name = name;
                    if (keystore->certificate) {
                        ue_logger_warn("Root certificate already exists in keystore object");
                        X509_free(x509);
                    } else {
                        keystore->certificate = ue_x509_certificate_create_empty();
                        ue_x509_certificate_set_impl(keystore->certificate, x509);
                    }
                }
            } else {
                if (keystore->other_certificates) {
                    ue_safe_realloc(keystore->other_certificates, ue_x509_certificate *, keystore->other_certificates_number, 1);
                } else {
                    ue_safe_alloc(keystore->other_certificates, ue_x509_certificate *, 1);
                }
                other_certificate = ue_x509_certificate_create_empty();
                ue_x509_certificate_set_impl(other_certificate, x509);
                keystore->other_certificates[keystore->other_certificates_number] = other_certificate;
                keystore->other_certificates_number++;
            }
            break;

        case NID_safeContentsBag:
            ue_logger_trace("NID_safeContentsBag");
            /*if (options & INFO)
                BIO_printf(bio_err, "Safe Contents bag\n");
            print_attribs(out, attrs, "Bag Attributes");*/
            return load_certs_pkeys_bags(keystore, PKCS12_SAFEBAG_get0_safes(bag), passphrase, passphrase_len, pem_passphrase, enc);

        default:
            ue_logger_warn("Warning unsupported bag type : '%s'", PKCS12_SAFEBAG_get0_type(bag));
            return true;
    }

    return true;
}

static int alg_print(const X509_ALGOR *alg) {
    int pbenid, aparamtype;
    const ASN1_OBJECT *aoid;
    const void *aparam;
    PBEPARAM *pbe = NULL;

    X509_ALGOR_get0(&aoid, &aparamtype, &aparam, alg);

    pbenid = OBJ_obj2nid(aoid);

    //BIO_printf(bio_err, "%s", OBJ_nid2ln(pbenid));

    /*
     * If PBE algorithm is PBES2 decode algorithm parameters
     * for additional details.
     */
    if (pbenid == NID_pbes2) {
        PBE2PARAM *pbe2 = NULL;
        int encnid;
        if (aparamtype == V_ASN1_SEQUENCE)
            pbe2 = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBE2PARAM));
        if (pbe2 == NULL) {
            //BIO_puts(bio_err, ", <unsupported parameters>");
            goto done;
        }
        X509_ALGOR_get0(&aoid, &aparamtype, &aparam, pbe2->keyfunc);
        pbenid = OBJ_obj2nid(aoid);
        X509_ALGOR_get0(&aoid, NULL, NULL, pbe2->encryption);
        encnid = OBJ_obj2nid(aoid);
        //BIO_printf(bio_err, ", %s, %s", OBJ_nid2ln(pbenid),
        //           OBJ_nid2sn(encnid));
        ue_logger_trace("encnid : %d", encnid);
        /* If KDF is PBKDF2 decode parameters */
        if (pbenid == NID_id_pbkdf2) {
            PBKDF2PARAM *kdf = NULL;
            int prfnid;
            if (aparamtype == V_ASN1_SEQUENCE)
                kdf = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBKDF2PARAM));
            if (kdf == NULL) {
                //BIO_puts(bio_err, ", <unsupported parameters>");
                goto done;
            }

            if (kdf->prf == NULL) {
                prfnid = NID_hmacWithSHA1;
            } else {
                X509_ALGOR_get0(&aoid, NULL, NULL, kdf->prf);
                prfnid = OBJ_obj2nid(aoid);
            }
            ue_logger_trace("prfnid : %d", prfnid);
            //BIO_printf(bio_err, ", Iteration %ld, PRF %s",
            //           ASN1_INTEGER_get(kdf->iter), OBJ_nid2sn(prfnid));
            PBKDF2PARAM_free(kdf);
#ifndef OPENSSL_NO_SCRYPT
        /*} else if (pbenid == NID_id_scrypt) {
            SCRYPT_PARAMS *kdf = NULL;

            if (aparamtype == V_ASN1_SEQUENCE)
                kdf = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(SCRYPT_PARAMS));
            if (kdf == NULL) {
                BIO_puts(bio_err, ", <unsupported parameters>");
                goto done;
            }
            BIO_printf(bio_err, ", Salt length: %d, Cost(N): %ld, "
                       "Block size(r): %ld, Paralelizm(p): %ld",
                       ASN1_STRING_length(kdf->salt),
                       ASN1_INTEGER_get(kdf->costParameter),
                       ASN1_INTEGER_get(kdf->blockSize),
                       ASN1_INTEGER_get(kdf->parallelizationParameter));
            SCRYPT_PARAMS_free(kdf);*/
#endif
        }
        PBE2PARAM_free(pbe2);
    } else {
        if (aparamtype == V_ASN1_SEQUENCE)
            pbe = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBEPARAM));
        if (pbe == NULL) {
            //BIO_puts(bio_err, ", <unsupported parameters>");
            goto done;
        }
        //BIO_printf(bio_err, ", Iteration %ld", ASN1_INTEGER_get(pbe->iter));
        PBEPARAM_free(pbe);
    }
 done:
    //BIO_puts(bio_err, "\n");
    return 1;
}
