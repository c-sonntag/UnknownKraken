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

#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/time/processor_timestamp.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/logger.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>

#if defined(__unix__) || defined(UNIX)
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
#endif

/**
 * source : https://stackoverflow.com/questions/8541396/data-types-conversion-unsigned-long-long-to-char
 */
unsigned char *ut_byte_to_long(unsigned long long nb) {
    unsigned char *buf;
    int i, j;

    ue_safe_alloc(buf, unsigned char, 22);
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

bool ue_crypto_random_seed_prng() {
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
        if (!(result = RAND_status())) {
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
                 * source : https://www.openssl.org/docs/man1.0.2/crypto/RAND_status.html
                 * RAND_event() for mouse movement and other user interactions
                 * RAND_screen() for collect screen content
                 */
            #endif

            if (seed_needed) {
                seed = ut_byte_to_long(ue_processor_timestamp());
                ue_safe_realloc(seed, unsigned char, 22, 16);
                RAND_seed(seed, 16);
                ue_safe_free(seed);
            }
            attempts++;
        }
    }

    if (!result) {
        ue_stacktrace_push_msg("Failed to seed PRNG of Openssl with %d attempts", attempts);
    } else {
        //ue_logger_trace("PRNG seeded");
    }

    return result;
}

bool ue_crypto_random_bytes(unsigned char *buffer, size_t buffer_length) {
    int attempts;
    char *error_buffer;

    attempts = 0;
    error_buffer = NULL;

    ue_crypto_random_seed_prng();

    while (RAND_bytes(buffer, buffer_length) != 1 && ++attempts != 5);

    if (attempts < 5) {
        return true;
    }

    ue_openssl_error_handling(error_buffer, "RAND_bytes but RAND_status returned true");
    return false;
}
