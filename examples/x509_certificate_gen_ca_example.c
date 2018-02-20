#include <unknownecho/init.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_generation.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/factory/x509_certificate_factory.h>

#include <stdio.h>

int main() {
    ue_x509_certificate *certificate;
    ue_private_key *private_key;

    certificate = NULL;
    private_key = NULL;

    ue_init();

    if (!ue_x509_certificate_generate_self_signed_ca("FR", "SWA", &certificate, &private_key)) {
        ue_logger_error("Failed to generate self signed CA");
        goto clean_up;
    }

    if (!ue_x509_certificate_print_pair(certificate, private_key, "ca_out/cert.pem", "ca_out/key.pem")) {
        ue_logger_error("Failed to print ca certificate and private key to files");
        goto clean_up;
    }

    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }

clean_up:
    ue_x509_certificate_destroy(certificate);
    ue_private_key_destroy(private_key);
    ue_uninit();
    return 0;
}
