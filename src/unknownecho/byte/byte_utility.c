#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/system/alloc.h>

#include <string.h>

unsigned char *ue_bytes_create_from_string(const char *str) {
	unsigned char *new_bytes;
	size_t len;

	len = strlen(str);

	ue_safe_alloc(new_bytes, unsigned char, len);
	memcpy(new_bytes, str, len * sizeof(unsigned char));

	return new_bytes;
}

unsigned char *ue_bytes_create_from_bytes(unsigned char *bytes, size_t size) {
	unsigned char *new_bytes;

	ue_safe_alloc(new_bytes, unsigned char, size);
	memcpy(new_bytes, bytes, size * sizeof(unsigned char));

	return new_bytes;
}

void ue_int_to_bytes(int n, unsigned char *bytes) {
	bytes[0] = (n >> 24) & 0xFF;
	bytes[1] = (n >> 16) & 0xFF;
	bytes[2] = (n >> 8) & 0xFF;
	bytes[3] = n & 0xFF;
}

int ue_bytes_to_int(unsigned char *bytes) {
	int n;
	n = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
	return n;
}
