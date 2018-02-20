#include <unknownecho/crypto/api/crypto_init.h>
#include <unknownecho/crypto/impl/openssl_init.h>

bool ue_crypto_init() {
	return ue_openssl_init();
}

void ue_crypto_uninit() {
	ue_openssl_uninit();
}
