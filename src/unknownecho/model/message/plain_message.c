#include <unknownecho/model/message/plain_message.h>
#include <unknownecho/model/entity/pgp_keystore.h>
#include <unknownecho/model/manager/pgp_keystore_manager.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/crypto/api/hash/hasher.h>
#include <unknownecho/crypto/api/signature/signer.h>
#include <unknownecho/crypto/factory/rsa_signer_factory.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_stream_struct.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_split.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/byte/hex_utility.h>

#include <string.h>
#include <stdio.h>

ue_plain_message *ue_plain_message_create_empty() {
	ue_plain_message *pmsg;

	ue_safe_alloc(pmsg, ue_plain_message, 1);
	pmsg->packet_type = NULL;
	pmsg->packet_type_len = 0;
	pmsg->destination_nickname = NULL;
	pmsg->destination_nickname_len = 0;
	pmsg->source_nickname = NULL;
	pmsg->source_nickname_len = 0;
	pmsg->signature = NULL;
	pmsg->signature_len = 0;
	pmsg->key = NULL;
	pmsg->key_len = 0;
	pmsg->iv = NULL;
	pmsg->iv_len = 0;
	pmsg->content = NULL;
	pmsg->content_len = 0;
	pmsg->content_len_uchar = NULL;
	pmsg->content_len_uchar_size = 0;

	return pmsg;
}

ue_plain_message *ue_plain_message_create(ue_pgp_keystore_manager *manager, char *dest_nickname, char *src_nickname, char *msg_content, char *message_type) {
	ue_plain_message *pmsg;

	pmsg = ue_plain_message_create_empty();

	ue_plain_message_fill(pmsg, manager, dest_nickname, src_nickname, msg_content, message_type);

	return pmsg;
}

void ue_plain_message_destroy(ue_plain_message *pmsg) {
	if (pmsg) {
		ue_safe_free(pmsg->packet_type);
		ue_safe_free(pmsg->destination_nickname);
		ue_safe_free(pmsg->source_nickname);
		ue_safe_free(pmsg->signature);
		ue_safe_free(pmsg->key);
		ue_safe_free(pmsg->iv);
		ue_safe_free(pmsg->content);
		ue_safe_free(pmsg->content_len_uchar);
		ue_safe_free(pmsg);
	}
}

void ue_plain_message_clean_up(ue_plain_message *pmsg) {
	if (pmsg) {
		ue_safe_free(pmsg->packet_type);
		pmsg->packet_type = NULL;
		pmsg->packet_type_len = 0;

		ue_safe_free(pmsg->destination_nickname);
		pmsg->destination_nickname = NULL;
		pmsg->destination_nickname_len = 0;

		ue_safe_free(pmsg->source_nickname);
		pmsg->source_nickname = NULL;
		pmsg->source_nickname_len = 0;

		ue_safe_free(pmsg->signature);
		pmsg->signature = NULL;
		pmsg->signature_len = 0;

		ue_safe_free(pmsg->key);
		pmsg->key = NULL;
		pmsg->key_len = 0;

		ue_safe_free(pmsg->iv);
		pmsg->iv = NULL;
		pmsg->iv_len = 0;

		ue_safe_free(pmsg->content);
		pmsg->content = NULL;
		pmsg->content_len = 0;

		ue_safe_free(pmsg->content_len_uchar);
		pmsg->content_len_uchar = NULL;
		pmsg->content_len_uchar_size = 0;
	}
}

/**
 * @todo update content_len_uchar from int to size_t type
 */
bool ue_plain_message_fill(ue_plain_message *pmsg, ue_pgp_keystore_manager *manager, char *dest_nickname, char *src_nickname, char *msg_content, char *message_type) {
	ue_pgp_keystore *keystore;
	ue_signer *s;

	keystore = NULL;
	s = NULL;

	if (!(keystore = ue_pgp_keystore_manager_get_keystore(manager))) {
		ue_stacktrace_push_msg("Failed to get pgp keystore");
		goto clean_up_fail;
	}

	pmsg->packet_type = ue_bytes_create_from_string(message_type);
	pmsg->packet_type_len = strlen(message_type);

	pmsg->destination_nickname = ue_bytes_create_from_string(dest_nickname);
	pmsg->destination_nickname_len = strlen(dest_nickname);

	pmsg->source_nickname = ue_bytes_create_from_string(src_nickname);
	pmsg->source_nickname_len = strlen(src_nickname);

	pmsg->content = ue_bytes_create_from_string(msg_content);
	pmsg->content_len = strlen(msg_content);

	/* Signature with message content digest */
	if (!(s = ue_rsa_signer_create(keystore->pk, keystore->sk))) {
        ue_stacktrace_push_msg("Failed to create rsa ue_signer with keystore key pair");
        goto clean_up_fail;
    }
	if (!(pmsg->signature = ue_signer_sign_buffer(s, pmsg->content, pmsg->content_len, &pmsg->signature_len))) {
        ue_stacktrace_push_msg("Failed to sign message with our private key");
        goto clean_up_fail;
    }

	/* Generate AES key of 32 bytes (because AES-CBC mode use here a key of 256 bits) */
	ue_safe_alloc(pmsg->key, unsigned char, 32);
	if (!(ue_crypto_random_bytes(pmsg->key, 32))) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for aes key generation");
		goto clean_up_fail;
	}
	pmsg->key_len = 32;

	/* Generate iv of 16 bytes (because AES-CBC block cipher is 128 bits) */
	ue_safe_alloc(pmsg->iv, unsigned char, 16);
	if (!(ue_crypto_random_bytes(pmsg->iv, 16))) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for IV");
		goto clean_up_fail;
	}
	pmsg->iv_len = 16;

	/* DeflateDecompress algorithm needs the plaintext size to proceed */
	ue_safe_alloc(pmsg->content_len_uchar, unsigned char, 4);
	ue_int_to_bytes((int)pmsg->content_len, pmsg->content_len_uchar);
	pmsg->content_len_uchar_size = 4;

	ue_signer_destroy(s);

	return true;

clean_up_fail:
	ue_signer_destroy(s);
	ue_plain_message_destroy(pmsg);
	return false;
}

static bool ue_plain_message_field_content_to_string_builder(ue_string_builder *builder, const char *message, unsigned char *field, size_t field_size, bool newline) {
	char *string;

	string = NULL;

	if (field) {
		if (!ue_string_builder_append(builder, (char *)message, strlen(message))) {
			ue_stacktrace_push_msg("Failed to append field header");
			return false;
		}
		string = ue_string_create_from_bytes(field, field_size);
		if (!ue_string_builder_append(builder, string, strlen(string))) {
			ue_stacktrace_push_msg("Failed to append field content");
			goto failed;
		}
		ue_safe_free(string);
		if (newline) {
			ue_string_builder_append(builder, "\n", strlen("\n"));
		}
	}

	return true;

failed:
	ue_safe_free(string);
	return false;
}

static bool ue_plain_message_field_content_to_string_builder_hex(ue_string_builder *builder, const char *message, unsigned char *field, size_t field_size) {
	char *hex;

	hex = NULL;

	if (field) {
		if (!ue_string_builder_append(builder, (char *)message, strlen(message))) {
			ue_stacktrace_push_msg("Failed to append field header");
			return false;
		}
		hex = ue_bytes_to_hex(field, field_size);
		if (!ue_string_builder_append(builder, hex, strlen(hex))) {
			ue_stacktrace_push_msg("Failed to append field content");
			goto failed;
		}
		ue_string_builder_append(builder, "\n", strlen("\n"));
		ue_safe_free(hex);
	}

	return true;

failed:
	return false;
}

char *ue_plain_message_to_string(ue_plain_message *pmsg) {
	char *string, *result;
	ue_string_builder *builder;

	string = NULL;
	result = NULL;
	builder = NULL;

	ue_check_parameter_or_return(pmsg);

	builder = ue_string_builder_create();

	if (!ue_plain_message_field_content_to_string_builder(builder, "Packet type : ", pmsg->packet_type, pmsg->packet_type_len, true)) {
		ue_stacktrace_push_msg("Failed to append packet type");
		goto clean_up;
	}

	if (!ue_plain_message_field_content_to_string_builder(builder, "Destination nickname : ", pmsg->destination_nickname, pmsg->destination_nickname_len, true)) {
		ue_stacktrace_push_msg("Failed to append destination nickname");
		goto clean_up;
	}

	if (!ue_plain_message_field_content_to_string_builder(builder, "Source nickname : ", pmsg->source_nickname, pmsg->source_nickname_len, true)) {
		ue_stacktrace_push_msg("Failed to append source nickname");
		goto clean_up;
	}

	if (!ue_plain_message_field_content_to_string_builder_hex(builder, "Signature : ", pmsg->signature, pmsg->signature_len)) {
		ue_stacktrace_push_msg("Failed to append signature");
		goto clean_up;
	}

	if (!ue_plain_message_field_content_to_string_builder_hex(builder, "Key : ", pmsg->key, pmsg->key_len)) {
		ue_stacktrace_push_msg("Failed to append key");
		goto clean_up;
	}

	if (!ue_plain_message_field_content_to_string_builder_hex(builder, "IV : ", pmsg->iv, pmsg->iv_len)) {
		ue_stacktrace_push_msg("Failed to append IV");
		goto clean_up;
	}

	if (!ue_plain_message_field_content_to_string_builder(builder, "Content : ", pmsg->content, pmsg->content_len, false)) {
		ue_stacktrace_push_msg("Failed to append content");
		goto clean_up;
	}

	string = ue_string_builder_get_data(builder);
	if (string) {
		result = ue_string_create_from(string);
	}

clean_up:
	ue_string_builder_destroy(builder);
	return result;
}

char *ue_plain_message_header_to_string(ue_plain_message *pmsg) {
	char *string, *result;
	ue_string_builder *builder;

	string = NULL;
	result = NULL;
	builder = NULL;

	ue_check_parameter_or_return(pmsg);

	if (!pmsg->packet_type) {
		ue_logger_warn("Specfied pmsg packet type is null");
		return NULL;
	}

	builder = ue_string_builder_create();

	if (!ue_plain_message_field_content_to_string_builder(builder, "Packet type : ", pmsg->packet_type, pmsg->packet_type_len, true)) {
		ue_stacktrace_push_msg("Failed to append packet type");
		goto clean_up;
	}

	if (!ue_plain_message_field_content_to_string_builder(builder, "Destination nickname : ", pmsg->destination_nickname, pmsg->destination_nickname_len, true)) {
		ue_stacktrace_push_msg("Failed to append destination nickname");
		goto clean_up;
	}

	if (!ue_plain_message_field_content_to_string_builder(builder, "Source nickname : ", pmsg->source_nickname, pmsg->source_nickname_len, true)) {
		ue_stacktrace_push_msg("Failed to append source nickname");
		goto clean_up;
	}

	string = ue_string_builder_get_data(builder);
	if (string) {
		result = ue_string_create_from(string);
	}

clean_up:
	ue_string_builder_destroy(builder);
	return result;
}

bool ue_plain_message_equals(ue_plain_message *pmsg1, ue_plain_message *pmsg2) {
	return pmsg1 && pmsg2 &&
		memcmp(pmsg1->packet_type, pmsg2->packet_type, pmsg1->packet_type_len) == 0 &&
		memcmp(pmsg1->destination_nickname, pmsg2->destination_nickname, pmsg1->destination_nickname_len) == 0 &&
		memcmp(pmsg1->source_nickname, pmsg2->source_nickname, pmsg1->source_nickname_len) == 0 &&
		memcmp(pmsg1->signature, pmsg2->signature, pmsg1->signature_len) == 0 &&
		memcmp(pmsg1->key, pmsg2->key, pmsg1->key_len) == 0 &&
		memcmp(pmsg1->iv, pmsg2->iv, pmsg1->iv_len) == 0 &&
		memcmp(pmsg1->content, pmsg2->content, pmsg1->content_len) == 0;
}

bool ue_plain_message_header_equals(ue_plain_message *pmsg1, ue_plain_message *pmsg2) {
	if (!pmsg1->packet_type) {
		ue_logger_warn("Packet type of pmsg1 is null");
		return false;
	}

	return pmsg1 && pmsg2 &&
		memcmp(pmsg1->packet_type, pmsg2->packet_type, pmsg1->packet_type_len) == 0 &&
		memcmp(pmsg1->destination_nickname, pmsg2->destination_nickname, pmsg1->destination_nickname_len) == 0 &&
		memcmp(pmsg1->source_nickname, pmsg2->source_nickname, pmsg1->source_nickname_len) == 0;
}

bool ue_plain_message_print(ue_plain_message *message) {
	char *string;

	if (message) {
		string = ue_plain_message_to_string(message);
		if (string) {
			printf("%s\n", string);
			ue_safe_free(string);
			return true;
		}
	}

	return false;
}
