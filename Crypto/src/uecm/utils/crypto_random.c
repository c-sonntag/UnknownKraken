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

#include <uecm/utils/crypto_random.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>

#include <ueum/ueum.h>

#include <ei/ei.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <limits.h>

#if defined(__unix__) || defined(UNIX)
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

/**
 * source : https://stackoverflow.com/questions/8541396/data-types-conversion-unsigned-long-long-to-char
 */
unsigned char *uecm_byte_to_long(unsigned long long nb) {
    unsigned char *buf;
    int i, j;

    buf = NULL;

    ueum_safe_alloc(buf, unsigned char, 22);
    i = 21;

    do {
        i--;
        buf[i] = nb % 10 + '0';
        nb = nb/10;
    } while (nb > 0);

    /* the number is stored from buf[i] to buf[21] */

    /* shifting the string to buf[0] : buf[21-i] */
    for (j = 0 ; j < 21 && i < 21 ; j++ , i++) {
        buf[j] = buf[i];
    }
    buf[j] = '\0';

    return buf;
}

bool uecm_crypto_random_seed_prng() {
    bool result, seed_needed;
    int attempts, max_attempts;
    unsigned char *seed;
#if defined(__linux__)
    int fd;
#endif

    result = false;
#if defined(__linux__)
    fd = -1;
#endif
    attempts = 0;
    max_attempts = 5;
    seed = NULL;
    seed_needed = false;

    /**
     * @todo test
     */
    while (!result && attempts < max_attempts) {
        if ((result = RAND_status()) == false) {
            #if defined(__unix__) || defined(UNIX)
                fd = open("/dev/urandom", S_IRUSR);
                if (fd < 0) {
                    seed_needed = true;
                } else {
                    close(fd);
                }
            #elif defined(_WIN32) || defined(_WIN64)
                /**
                 * @todo add this Windows-only functions to increase the entropy
                 * source : https://www.openssl.org/docs/man1.0.2/RAND_status.html
                 * RAND_event() for mouse movement and other user interactions
                 * RAND_screen() for collect screen content
                 */
            #endif

            if (seed_needed) {
                seed = uecm_byte_to_long(ueum_processor_timestamp());
                ueum_safe_realloc(seed, unsigned char, 22, 16);
                RAND_seed(seed, 16);
                ueum_safe_free(seed);
            }
            attempts++;
        }
    }

    if (!result) {
        ei_stacktrace_push_msg("Failed to seed PRNG of Openssl with %d attempts", attempts);
    } else {
        //ei_logger_trace("PRNG seeded");
    }

    return result;
}

bool uecm_crypto_random_bytes(unsigned char *buffer, size_t buffer_length) {
    int attempts;
    char *error_buffer;

    ei_check_parameter_or_return(buffer)
    ei_check_parameter_or_return(buffer_length > 0)

    if (buffer_length > UINT_MAX) {
        ei_stacktrace_push_msg("RAND_bytes() need a length in int, however buffer_length is > UINT_MAX");
        return false;
    }

    attempts = 0;
    error_buffer = NULL;

    uecm_crypto_random_seed_prng();

    while (RAND_bytes(buffer, (int)buffer_length) != 1 && ++attempts != 5);

    if (attempts < 5) {
        return true;
    }

    uecm_openssl_error_handling(error_buffer, "RAND_bytes but RAND_status returned true");
    return false;
}
