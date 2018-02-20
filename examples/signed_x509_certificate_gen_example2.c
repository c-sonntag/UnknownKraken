#include <unknownecho/init.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_generation.h>
#include <unknownecho/crypto/api/key/private_key.h>

#include <stdio.h>

int main() {
    ue_x509_certificate *ca_certificate, *client1_certificate, *client2_certificate, *server_certificate;
    ue_private_key *ca_private_key, *client1_private_key, *client2_private_key, *server_private_key;

    ca_certificate = NULL;
    ca_private_key = NULL;
    server_certificate = NULL;
    server_private_key = NULL;
    client1_certificate = NULL;
    client1_private_key = NULL;
    client2_certificate = NULL;
    client2_private_key = NULL;

    ue_init();

    if (!ue_x509_certificate_generate_self_signed_ca("FR", "SWA", &ca_certificate, &ca_private_key)) {
        ue_logger_error("Failed to generate self signed CA");
        goto clean_up;
    }

    if (!ue_x509_certificate_print_pair(ca_certificate, ca_private_key, "res/tls3/ca.pem", "res/tls3/key.pem")) {
        ue_logger_error("Failed to print ca certificate and private key to files");
        goto clean_up;
    }

    if (!ue_x509_certificate_generate_signed(ca_certificate, ca_private_key, "FR", "SERVER", &server_certificate, &server_private_key)) {
        ue_logger_error("Failed to generate certificate signed by CA, for server");
        goto clean_up;
    }

    if (!ue_x509_certificate_print_pair(ca_certificate, ca_private_key, "res/tls3/ssl_server.crt", "res/tls3/ssl_server.key")) {
        ue_logger_error("Failed to print signed certificate and private key to files, for server");
        goto clean_up;
    }

    if (!ue_x509_certificate_generate_signed(ca_certificate, ca_private_key, "FR", "CLIENT1", &client1_certificate, &client1_private_key)) {
        ue_logger_error("Failed to generate certificate signed by CA, for client 1");
        goto clean_up;
    }

    if (!ue_x509_certificate_print_pair(ca_certificate, ca_private_key, "res/tls3/ssl_client1.crt", "res/tls3/ssl_client1.key")) {
        ue_logger_error("Failed to print signed certificate and private key to files, for client 1");
        goto clean_up;
    }

    if (!ue_x509_certificate_generate_signed(ca_certificate, ca_private_key, "FR", "CLIENT2", &client2_certificate, &client2_private_key)) {
        ue_logger_error("Failed to generate certificate signed by CA, for client 2");
        goto clean_up;
    }

    if (!ue_x509_certificate_print_pair(ca_certificate, ca_private_key, "res/tls3/ssl_client2.crt", "res/tls3/ssl_client2.key")) {
        ue_logger_error("Failed to print signed certificate and private key to files, for client 2");
        goto clean_up;
    }

    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }

clean_up:
    ue_x509_certificate_destroy(ca_certificate);
    ue_private_key_destroy(ca_private_key);
    ue_x509_certificate_destroy(server_certificate);
    ue_private_key_destroy(server_private_key);
    ue_x509_certificate_destroy(client1_certificate);
    ue_private_key_destroy(client1_private_key);
    ue_x509_certificate_destroy(client2_certificate);
    ue_private_key_destroy(client2_private_key);
    ue_uninit();
    return 0;
}
