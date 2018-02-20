#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/string/string_utility.h>

#include <openssl/err.h>

char *ue_openssl_error_handling_impl(char *begin_msg) {
	unsigned long error_code;
	char *error_buffer;

	error_buffer = NULL;

	error_code = ERR_get_error();
	error_buffer = (char *)ERR_reason_error_string(error_code);
	if (error_buffer) {
		error_buffer = ue_strcat_variadic("ssss", begin_msg, " - failed with error msg `", error_buffer, "`");
	} else {
		error_buffer = ue_strcat_variadic("ssl", begin_msg, " - failed with error code ", error_code);
	}

	return error_buffer;
}
