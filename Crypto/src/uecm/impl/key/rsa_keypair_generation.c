/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
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

#include <uecm/impl/key/rsa_keypair_generation.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <uecm/utils/crypto_random.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <openssl/bn.h>

static int genrsa_callback(int p, int n, BN_GENCB *cb) {
    ueum_progress_bar *progress_bar;

    if (p != 0) {
        progress_bar = (ueum_progress_bar *)BN_GENCB_get_arg(cb);
        ueum_progress_bar_update_by_increasing_and_print(progress_bar, 10);
    }

    return 1;
}

RSA *uecm_rsa_keypair_gen(int bits) {
    RSA *rsa_key_pair;
    unsigned long e;
    int ret;
    BIGNUM *bne;
    char *error_buffer;
    BN_GENCB *cb;
    ueum_progress_bar *progress_bar;
    char *progress_bar_description;

    if (bits != 2048 && bits != 4096) {
        return NULL;
    }

    rsa_key_pair = NULL;
    bne = NULL;
    e = RSA_F4;
    error_buffer = NULL;
    cb = BN_GENCB_new();
    progress_bar = NULL;
    progress_bar_description = NULL;

    /* Create a pretty progress bar */

    /* Build progress bar description */
    if ((progress_bar_description = ueum_strcat_variadic("sds", "Generating ", bits, " bits RSA key")) == NULL) {
        ei_stacktrace_push_msg("Failed to create progress bar description");
        goto clean_up;
    }

    /* Create progress bar ptr with a max size of 100 */
    progress_bar = ueum_progress_bar_create(100, progress_bar_description, stdout);

    /* Doesn't support Windows coloring for now */
#ifdef _WINDOWS
    ueum_progress_bar_set_style(progress_bar, "|", "-");
#else
    ueum_progress_bar_set_colors(progress_bar, UNKNOWNECHOUTILSMODULE_COLOR_ID_ATTRIBUTE_DIM, UNKNOWNECHOUTILSMODULE_COLOR_ID_FOREGROUND_GREEN, -1);
    ueum_progress_bar_set_style(progress_bar, "\u2588", "-");
#endif

    /* Seed the PRNG to increase the entropy */
    if (!uecm_crypto_random_seed_prng()) {
        ei_stacktrace_push_msg("Failed to seed PRNG");
        goto clean_up;
    }

    if ((rsa_key_pair = RSA_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "RSA_new");
        goto clean_up;
    }

    if ((bne = BN_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "BN_new");
        RSA_free(rsa_key_pair);
        rsa_key_pair = NULL;
        goto clean_up;
    }

    if ((ret = BN_set_word(bne, e)) != 1) {
        uecm_openssl_error_handling(error_buffer, "BN_set_word");
        RSA_free(rsa_key_pair);
        rsa_key_pair = NULL;
        goto clean_up;
    }

    BN_GENCB_set(cb, genrsa_callback, progress_bar);

    if (!(ret = RSA_generate_key_ex(rsa_key_pair, bits, bne, cb))) {
        uecm_openssl_error_handling(error_buffer, "RSA_generate_key_ex");
        RSA_free(rsa_key_pair);
        rsa_key_pair = NULL;
        goto clean_up;
    }
    ueum_progress_bar_finish_and_print(progress_bar);
    if ((ret = RSA_generate_key_ex(rsa_key_pair, bits, bne, NULL)) == 0) {
        uecm_openssl_error_handling(error_buffer, "RSA_generate_key_ex");
        RSA_free(rsa_key_pair);
        rsa_key_pair = NULL;
        goto clean_up;
    }

    /**
     * @todo fix this
     */
    //fprintf(ei_logger_get_fp(ei_logger_manager_get_logger()), "\n");

    fprintf(stdout, "\n");
    ei_logger_trace("RSA key generated");

clean_up:
    BN_GENCB_free(cb);
    BN_clear_free(bne);
    ueum_safe_free(progress_bar_description);
    ueum_progress_bar_destroy(progress_bar);
    return rsa_key_pair;
}
