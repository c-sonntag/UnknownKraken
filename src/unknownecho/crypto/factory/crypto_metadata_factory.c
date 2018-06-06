#include <unknownecho/crypto/factory/crypto_metadata_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/factory/x509_certificate_factory.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/string/string_utility.h>
#include <ei/ei.h>
#include <unknownecho/defines.h>
#include <unknownecho/alloc.h>
#include <unknownecho/fileSystem/file_utility.h>

ue_crypto_metadata *ue_crypto_metadata_create_default() {
    ue_crypto_metadata *crypto_metadata;
    ue_x509_certificate *cipher_certificate, *signer_certificate;
    ue_private_key *cipher_private_key, *signer_private_key;
    const char *cipher_name, *digest_name;
    ue_sym_key *sym_key;

    crypto_metadata = ue_crypto_metadata_create_empty();
    cipher_certificate = NULL;
    signer_certificate = NULL;
    cipher_private_key = NULL;
    signer_private_key = NULL;
    cipher_name = NULL;
    digest_name = NULL;
    sym_key = NULL;

    if (!ue_x509_certificate_generate_self_signed_ca("CIPHER", &cipher_certificate, &cipher_private_key)) {
        ei_stacktrace_push_msg("Failed to generate self signed CA for CIPHER");
        goto clean_up_fail;
    }

    if (!ue_x509_certificate_generate_self_signed_ca("SIGNER", &signer_certificate, &signer_private_key)) {
        ei_stacktrace_push_msg("Failed to generate self signed CA for SIGNER");
        goto clean_up_fail;
    }

    if (!(cipher_name = ue_string_create_from(UNKNOWNECHO_DEFAULT_CIPHER_NAME))) {
        ei_stacktrace_push_msg("Failed to get default cipher name");
        goto clean_up_fail;
    }

    if (!(digest_name = ue_string_create_from(UNKNOWNECHO_DEFAULT_DIGEST_NAME))) {
        ei_stacktrace_push_msg("Failed to get default digest name");
        goto clean_up_fail;
    }

    if (!(sym_key = ue_sym_key_create_random())) {
        ei_stacktrace_push_msg("Failed to generate random sym key");
        goto clean_up_fail;
    }

    if (!ue_crypto_metadata_set_cipher_certificate(crypto_metadata, cipher_certificate)) {
        ei_stacktrace_push_msg("Failed to set cipher certificate to crypto metadata");
        goto clean_up_fail;
    }

    if (!ue_crypto_metadata_set_signer_certificate(crypto_metadata, signer_certificate)) {
        ei_stacktrace_push_msg("Failed to set signer certificate to crypto metadata");
        goto clean_up_fail;
    }

    if (!ue_crypto_metadata_set_cipher_private_key(crypto_metadata, cipher_private_key)) {
        ei_stacktrace_push_msg("Failed to set cipher private key to crypto metadata");
        goto clean_up_fail;
    }

    if (!ue_crypto_metadata_set_signer_private_key(crypto_metadata, signer_private_key)) {
        ei_stacktrace_push_msg("Failed to set signer private key to crypto metadata");
        goto clean_up_fail;
    }

    if (!ue_crypto_metadata_set_cipher_name(crypto_metadata, cipher_name)) {
        ei_stacktrace_push_msg("Failed to set cipher name to crypto metadata");
        goto clean_up_fail;
    }

    if (!ue_crypto_metadata_set_digest_name(crypto_metadata, digest_name)) {
        ei_stacktrace_push_msg("Failed to set digest name to crypto metadata");
        goto clean_up_fail;
    }

    if (!ue_crypto_metadata_set_sym_key(crypto_metadata, sym_key)) {
        ei_stacktrace_push_msg("Failed to set sym key to crypto metadata");
        goto clean_up_fail;
    }

    return crypto_metadata;

clean_up_fail:
    ue_x509_certificate_destroy(cipher_certificate);
    ue_x509_certificate_destroy(signer_certificate);
    ue_private_key_destroy(cipher_private_key);
    ue_private_key_destroy(signer_private_key);
    ue_crypto_metadata_destroy(crypto_metadata);
    ue_safe_free(cipher_name);
    ue_safe_free(digest_name);
    ue_sym_key_destroy(sym_key);
    return NULL;
}

ue_crypto_metadata *ue_crypto_metadata_write_if_not_exist(const char *private_folder, const char *
    certificates_folder, const char *uid, const char *password) {

    ue_crypto_metadata *our_crypto_metadata;

    ei_check_parameter_or_return(private_folder);
    ei_check_parameter_or_return(certificates_folder);
    ei_check_parameter_or_return(uid);
    ei_check_parameter_or_return(password);

    our_crypto_metadata = NULL;

    ei_logger_trace("Checking if crypto metadata already exists...");
    if (!ue_crypto_metadata_exists(private_folder, uid)) {
        if (ei_stacktrace_is_filled()) {
            ei_logger_stacktrace("Failed to check if crypto metadata already exists");
            ei_stacktrace_clean_up();
        }
        if (!(our_crypto_metadata = ue_crypto_metadata_create_default())) {
            ei_stacktrace_push_msg("Failed to create random crypto metadata");
            ue_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
        ei_logger_trace("Writing crypto metadata...");
        if (!ue_crypto_metadata_write(our_crypto_metadata, private_folder, uid, password)) {
            ei_stacktrace_push_msg("Failed to write our crypto metadata in secure files");
            ue_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
    } else {
        if (!(our_crypto_metadata = ue_crypto_metadata_create_empty())) {
            ei_stacktrace_push_msg("Failed to create empty crypto metadata");
            ue_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
        ei_logger_trace("Crypto metadata already exists");
        if (!ue_crypto_metadata_read(our_crypto_metadata, private_folder, uid, password)) {
            ei_stacktrace_push_msg("Failed to read our crypto metadata");
            ue_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
    }

    ei_logger_trace("Checking if certificates already exists...");
    if (!ue_crypto_metadata_certificates_exists(certificates_folder, uid)) {
        if (ei_stacktrace_is_filled()) {
            ei_logger_stacktrace("Failed to check if certificates already exists");
            ei_stacktrace_clean_up();
        }
        ei_logger_trace("Writing certificates...");
        if (!ue_crypto_metadata_write_certificates(our_crypto_metadata, certificates_folder, uid)) {
            ei_stacktrace_push_msg("Failed to write our certificates in public folder");
            ue_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
    } else {
        ei_logger_trace("Certificates already exists");
        ei_logger_trace("Reading certificates...");
        if (!ue_crypto_metadata_read_certificates(our_crypto_metadata, certificates_folder, uid)) {
            ei_stacktrace_push_msg("Failed to read certificates");
            ue_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
    }

    return our_crypto_metadata;
}
