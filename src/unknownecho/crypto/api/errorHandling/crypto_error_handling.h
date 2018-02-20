#ifndef UNKNOWNECHO_CRYPTO_ERROR_HANDLING_H
#define UNKNOWNECHO_CRYPTO_ERROR_HANDLING_H

#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>

#define ue_crypto_error_handling(error_buffer, begin_msg) \
    ue_openssl_error_handling(error_buffer, begin_msg) \

#endif
