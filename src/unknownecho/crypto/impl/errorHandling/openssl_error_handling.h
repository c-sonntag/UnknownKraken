#ifndef UNKNOWNECHO_OPENSSL_ERROR_HANDLING_H
#define UNKNOWNECHO_OPENSSL_ERROR_HANDLING_H

#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/system/alloc.h>

char *ue_openssl_error_handling_impl(char *begin_msg);

#define ue_openssl_error_handling(error_buffer, begin_msg) \
	do { \
		error_buffer = ue_openssl_error_handling_impl(begin_msg); \
		ue_stacktrace_push_msg(error_buffer) \
		ue_safe_str_free(error_buffer) \
	} while (0); \

#endif
