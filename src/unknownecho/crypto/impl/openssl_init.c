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

#include <unknownecho/crypto/impl/openssl_init.h>
#include <unknownecho/alloc.h>
#include <ei/ei.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

#if defined (_WIN32) || (_WIN64)
	#include <windows.h>
#else
	#include <pthread.h>
#endif

/* This array will store all of the mutexes available to OpenSSL */
#if defined (_WIN32) || (_WIN64)
	CRITICAL_SECTION *mutex_buf = 0;
#else
	pthread_mutex_t *mutex_buf = 0;
#endif

/* OpenSSL callback to utilize static locks */
void openssl_locking_function_callback(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
    	#if defined(_WIN32) || defined(_WIN64)
        	EnterCriticalSection(&mutex_buf[n]);
    	#else
    		pthread_mutex_lock(&mutex_buf[n]);
    	#endif
    }
    else {
    	#if defined(_WIN32) || defined(_WIN64)
        	LeaveCriticalSection(&mutex_buf[n]);
    	#else
        	pthread_mutex_unlock(&mutex_buf[n]);
    	#endif
    }
}

unsigned long openssl_id_function_callback() {
	#if defined(_WIN32) || defined(_WIN64)
		return ((unsigned long)GetCurrentThreadId());
	#else
		return ((unsigned long)pthread_self());
	#endif
}

static bool alloc_mutexes() {
    int i, total;

    total = CRYPTO_num_locks();

    #if defined(_WIN32) || defined(_WIN64)
    	ue_safe_alloc(mutex_buf, CRITICAL_SECTION, total);
    #else
    	ue_safe_alloc(mutex_buf, pthread_mutex_t, total);
    #endif

    for (i = 0; i < total;  i++) {
    	#if defined(_WIN32) || defined(_WIN64)
        	InitializeCriticalSection(&(mutex_buf[i]));
    	#else
			pthread_mutex_init(&(mutex_buf[i]), 0);
    	#endif
    }

    return true;
}

static void dealloc_mutexes() {
    int i;

    CRYPTO_set_locking_callback(0);
    CRYPTO_set_dynlock_create_callback(0);
    CRYPTO_set_dynlock_lock_callback(0);
    CRYPTO_set_dynlock_destroy_callback(0);

    for (i = 0; i < CRYPTO_num_locks(); i++) {
    	#if defined(_WIN32) || defined(_WIN64)
			DeleteCriticalSection(&mutex_buf[i]);
		#else
			pthread_mutex_destroy(&(mutex_buf[i]));
		#endif
    }

    ue_safe_free(mutex_buf);
    mutex_buf = NULL;
}

bool ue_openssl_init() {
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	/* Load the strings and init the library */
	SSL_load_error_strings();

	if (!alloc_mutexes()) {
		ei_stacktrace_push_msg("Failed to alloc mutexes");
		return false;
	}

	CRYPTO_set_id_callback(openssl_id_function_callback);
    CRYPTO_set_locking_callback(openssl_locking_function_callback);

    return true;
}

void ue_openssl_uninit() {
	RAND_cleanup();
	dealloc_mutexes();
	FIPS_mode_set(0);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();

	SSL_COMP_free_compression_methods();
}
