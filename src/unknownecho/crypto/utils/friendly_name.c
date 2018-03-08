#include <unknownecho/crypto/utils/friendly_name.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/alloc.h>

#include <string.h>

unsigned char *ue_friendly_name_build(unsigned char *nickname, size_t nickname_size, char *keystore_type, size_t *friendly_name_size) {
	unsigned char *friendly_name;

	ue_check_parameter_or_return(nickname);
	ue_check_parameter_or_return(nickname_size > 0);
	ue_check_parameter_or_return(keystore_type);

	*friendly_name_size = nickname_size + 1 + strlen(keystore_type);
	ue_safe_alloc(friendly_name, unsigned char, *friendly_name_size);
	memcpy(friendly_name, nickname, nickname_size * sizeof(unsigned char));
	memcpy(friendly_name + nickname_size, "_", sizeof(unsigned char));
	memcpy(friendly_name + nickname_size + 1, keystore_type, strlen(keystore_type) * sizeof(unsigned char));

	return friendly_name;
}
