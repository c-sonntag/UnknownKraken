#include <unknownecho/crypto/api/encoding/base64_encode.h>
#include <unknownecho/crypto/impl/encoding/base64_encode_impl.h>

unsigned char *ue_base64_encode(const unsigned char *src, size_t len, size_t *out_len) {
	size_t tmp_out_len;
	unsigned char *result;

	result = ue_base64_encode_impl(src, len, &tmp_out_len);

	*out_len = tmp_out_len;

	return result;
}
