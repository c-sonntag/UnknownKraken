#include <unknownecho/init.h>
#include <unknownecho/thread/thread_storage.h>
#include <unknownecho/crypto/api/crypto_init.h>
#include <unknownecho/bool.h>
#include <unknownecho/errorHandling/logger_manager.h>

static bool ue_thread_storage_initialized = false;
static bool crypto_initialized = false;

int ue_init() {
	if (!ue_thread_storage_initialized) {
		ue_thread_storage_initialized = ue_thread_storage_init();
	}

	if (ue_thread_storage_initialized && !crypto_initialized) {
		crypto_initialized = ue_crypto_init();
	}

	ue_logger_manager_init();

	return ue_thread_storage_initialized && crypto_initialized;
}

void ue_uninit() {
	if (crypto_initialized) {
		ue_crypto_uninit();
	}

	if (ue_thread_storage_initialized) {
		ue_thread_storage_uninit();
	}

	ue_logger_manager_uninit();
}
