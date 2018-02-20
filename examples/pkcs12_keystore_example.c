#include <unknownecho/init.h>
#include <unknownecho/bool.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>

#include <stdio.h>

int main(int argc, char **argv) {
    ue_pkcs12_keystore *keystore;

    if (argc != 4) {
        fprintf(stderr, "[ERROR] ./%s <file_path> <pass_phrase> <pem_pass_phrase>\n", argv[0]);
    }

    ue_init();

    if (!(keystore = ue_pkcs12_keystore_load(argv[1], argv[2], argv[3]))) {
        ue_stacktrace_push_msg("Failed to loas specified pkcs12 keystore");
        goto clean_up;
    }

    if (!ue_pkcs12_keystore_write(keystore, "out/keystore.p12", argv[2], argv[3])) {
        ue_stacktrace_push_msg("Failed to write keystore to 'out/keystore.p12'");
        goto clean_up;
    }

clean_up:
    ue_pkcs12_keystore_destroy(keystore);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
}
