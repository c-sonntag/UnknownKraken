#include <unknownecho/crypto/impl/key/rsa_keypair_generation.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/console/progress_bar.h>
#include <unknownecho/console/color.h>
#include <unknownecho/string/string_utility.h>
#include <ei/ei.h>
#include <unknownecho/alloc.h>

#include <openssl/bn.h>

static int genrsa_callback(int p, int n, BN_GENCB *cb) {
    ue_progress_bar *progress_bar;

    if (p != 0) {
        progress_bar = (ue_progress_bar *)BN_GENCB_get_arg(cb);
        ue_progress_bar_update_by_increasing_and_print(progress_bar, 10);
    }

    return 1;
}

RSA *ue_rsa_keypair_gen(int bits) {
    RSA *rsa_key_pair;
    unsigned long e;
    int ret;
    BIGNUM *bne;
    char *error_buffer;
    BN_GENCB *cb;
    ue_progress_bar *progress_bar;
    const char *progress_bar_description;

    if (bits != 2048 && bits != 4096) {
        return NULL;
    }

    rsa_key_pair = NULL;
    bne = NULL;
    e = RSA_F4;
    error_buffer = NULL;
    cb = BN_GENCB_new();

    /* Create a pretty progress bar */

    /* Build progress bar description */
    progress_bar_description = ue_strcat_variadic("sds", "Generating ", bits, " bits RSA key");

    /* Create progress bar ptr with a max size of 100 */
    progress_bar = ue_progress_bar_create(100, progress_bar_description, stdout);

    /* Doesn't support Windows coloring for now */
#ifdef _WINDOWS
    ue_progress_bar_set_style(progress_bar, "|", "-");
#else
    ue_progress_bar_set_colors(progress_bar, UNKNOWNECHO_COLOR_ID_ATTRIBUTE_DIM, UNKNOWNECHO_COLOR_ID_FOREGROUND_GREEN, -1);
    ue_progress_bar_set_style(progress_bar, "\u2588", "-");
#endif

    /* Seed the PRNG to increase the entropy */
    if (!ue_crypto_random_seed_prng()) {
        ei_stacktrace_push_msg("Failed to seed PRNG");
        goto clean_up;
    }

    if (!(rsa_key_pair = RSA_new())) {
        ue_openssl_error_handling(error_buffer, "RSA_new");
        goto clean_up;
    }

    if (!(bne = BN_new())) {
        ue_openssl_error_handling(error_buffer, "BN_new");
        RSA_free(rsa_key_pair);
        rsa_key_pair = NULL;
        goto clean_up;
    }

    if ((ret = BN_set_word(bne, e)) != 1) {
        ue_openssl_error_handling(error_buffer, "BN_set_word");
        RSA_free(rsa_key_pair);
        rsa_key_pair = NULL;
        goto clean_up;
    }

    BN_GENCB_set(cb, genrsa_callback, progress_bar);

    if (!(ret = RSA_generate_key_ex(rsa_key_pair, bits, bne, cb))) {
        ue_openssl_error_handling(error_buffer, "RSA_generate_key_ex");
        RSA_free(rsa_key_pair);
        rsa_key_pair = NULL;
        goto clean_up;
    }
    ue_progress_bar_finish(progress_bar);

    ei_logger_trace("RSA key generated");

clean_up:
    BN_GENCB_free(cb);
    BN_clear_free(bne);
    ue_safe_free(progress_bar_description);
    ue_progress_bar_destroy(progress_bar);
    return rsa_key_pair;
}
