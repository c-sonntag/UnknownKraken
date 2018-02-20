#include <unknownecho/model/message/decipher_message.h>
#include <unknownecho/model/message/cipher_message.h>
#include <unknownecho/model/message/plain_message.h>
#include <unknownecho/model/entity/pgp_keystore.h>
#include <unknownecho/model/manager/pgp_keystore_manager.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/time/timer.h>
#include <unknownecho/crypto/api/encryption/asym_encrypter.h>
#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/api/compression/compress.h>
#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/signature/signer.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/crypto/factory/asym_encrypter_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/factory/rsa_signer_factory.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_stream_struct.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/byte/hex_utility.h>

static bool build_decrypted_server_header(ue_pgp_keystore *keystore, ue_plain_message *pmsg, ue_cipher_message *cmsg) {
	bool succeed;
	unsigned char *server_aes_key_tmp, *server_aes_iv, *decompressed_len_uchar, *compressed, *decompressed,
		*key_header, *server_content_field, *ciphered;
	size_t decompressed_len, ciphered_len, key_header_len, compressed_len;
	int deciphered_len, read_int, server_aes_key_len_tmp, server_aes_iv_len, decompressed_len_uchar_len,
		server_content_field_len;
	ue_byte_stream *server_header_stream, *server_header_content_stream, *key_header_stream;
	ue_sym_key *server_aes_key;
	ue_asym_encrypter *asencrypter;
	ue_sym_encrypter *sencrypter;

	succeed = false;
	server_aes_key = NULL;
	server_aes_iv = NULL;
	decompressed_len_uchar = NULL;
	compressed = NULL;
	decompressed = NULL;
	server_header_stream = ue_byte_stream_create();
	server_header_content_stream = ue_byte_stream_create();
	key_header_stream = ue_byte_stream_create();
	server_content_field = NULL;
	ciphered = NULL;
	key_header = NULL;
	sencrypter = NULL;
	asencrypter = NULL;
	server_aes_key_tmp = NULL;

	/* ============ ServerHeader spliting ============ */

	if (!ue_byte_writer_append_bytes(server_header_stream, cmsg->server_header, cmsg->server_header_size)) {
		ue_stacktrace_push_msg("Failed to write ciphered raw message to server header stream");
		goto clean_up;
	}
	ue_logger_trace("Added server header to byte stream");

	ue_byte_stream_set_position(server_header_stream, 0);

	if (!ue_byte_read_next_int(server_header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <ciphered_key_header_len> field");
		goto clean_up;
	}
	ciphered_len = read_int;
	ue_logger_trace("ciphered_len : %ld", ciphered_len);

	/* <server_content_field_len> */
	if (!ue_byte_read_next_int(server_header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <server_content_field_len> field");
		goto clean_up;
	}
	server_content_field_len = (size_t)read_int;
	ue_logger_trace("server_content_field_len : %ld", server_content_field_len);

	/* <key_header> */
	if (!ue_byte_read_next_bytes(server_header_stream, &ciphered, ciphered_len)) {
		ue_stacktrace_push_msg("Failed to parse <key_header> field");
		goto clean_up;
	}

	ue_logger_trace("Key header read");
	char *hex = ue_bytes_to_hex(ciphered, ciphered_len);
	ue_logger_trace("Key header : %s", hex);
	ue_safe_free(hex);

	/* <server_content_field> */
	if (!ue_byte_read_next_bytes(server_header_stream, &server_content_field, (size_t)server_content_field_len)) {
		ue_stacktrace_push_msg("Failed to parse <receiver_content_field> field");
		goto clean_up;
	}

	ue_logger_trace("Server content field");
	hex = ue_bytes_to_hex(server_content_field, server_content_field_len);
	ue_logger_trace("Server content field : %s", hex);
	ue_safe_free(hex);

	/* ============ ServerHeader AES key field decryption ============ */

	asencrypter = ue_asym_encrypter_default_create(NULL, keystore->sk);

	if (!(key_header = ue_asym_encrypter_private_decrypt(asencrypter, ciphered, ciphered_len, &key_header_len))) {
		ue_stacktrace_push_msg("Failed to decrypt key header with our private key");
		goto clean_up;
	}
	ue_logger_trace("key_header_len : %ld", key_header_len);

	if (!ue_byte_writer_append_bytes(key_header_stream, key_header, key_header_len)) {
		ue_stacktrace_push_msg("Failed to append key header");
		goto clean_up;
	}

	ue_byte_stream_set_position(key_header_stream, 0);

	// <server_aes_key_len>
	if (!ue_byte_read_next_int(key_header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <server_aes_key_len> field");
		goto clean_up;
	}
	server_aes_key_len_tmp = (size_t)read_int;
	ue_logger_trace("server_aes_key_len_tmp : %ld", server_aes_key_len_tmp);

	// <server_aes_iv_len>
	if (!ue_byte_read_next_int(key_header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <server_aes_iv_len> field");
		goto clean_up;
	}
	server_aes_iv_len = (size_t)read_int;
	ue_logger_trace("server_aes_iv_len : %ld", server_aes_iv_len);

	// <decompressed_len_uchar_len>
	if (!ue_byte_read_next_int(key_header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <decompressed_len_uchar_len> field");
		goto clean_up;
	}
	decompressed_len_uchar_len = (size_t)read_int;

	// <server_aes_key>
	if (!ue_byte_read_next_bytes(key_header_stream, &server_aes_key_tmp, (size_t)server_aes_key_len_tmp)) {
		ue_stacktrace_push_msg("Failed to parse <server_aes_key> field");
		goto clean_up;
	}
	server_aes_key = ue_sym_key_create(server_aes_key_tmp, server_aes_key_len_tmp);

	// <server_aes_iv>
	if (!ue_byte_read_next_bytes(key_header_stream, &server_aes_iv, (size_t)server_aes_iv_len)) {
		ue_stacktrace_push_msg("Failed to parse <server_aes_iv> field");
		goto clean_up;
	}

	// <decompressed_len_uchar>
	if (!ue_byte_read_next_bytes(key_header_stream, &decompressed_len_uchar, (size_t)decompressed_len_uchar_len)) {
		ue_stacktrace_push_msg("Failed to parse <decompressed_len_uchar> field");
		goto clean_up;
	}

	deciphered_len = ue_bytes_to_int(decompressed_len_uchar);


	/* =============== ServerHeader content field decryption ============ */

	/* Decrypt the fourth part with the previous AES key and IV */
	sencrypter = ue_sym_encrypter_default_create(server_aes_key);
	if (!(compressed = ue_sym_encrypter_decrypt(sencrypter, server_content_field, server_content_field_len, server_aes_iv, server_aes_iv_len, &compressed_len))) {
		ue_stacktrace_push_msg("Failed to decrypt ServerHeader content");
		goto clean_up;
	}

	ue_logger_trace("deciphered_len : %ld", deciphered_len);

	/* Decompress the fourth part with the previous known decompressed len */
	if (!(decompressed = ue_decompress_buf(compressed, compressed_len, deciphered_len))) {
		ue_stacktrace_push_msg("Failed to decompress ServerHeader content");
		goto clean_up;
	}
	decompressed_len = deciphered_len;

	/* Fill a byte stream with the payload of ServerHeader */
	if (!ue_byte_writer_append_bytes(server_header_content_stream, decompressed, decompressed_len)) {
		ue_stacktrace_push_msg("Failed to append ServerHeader bytes to byte stream");
		goto clean_up;
	}

	ue_safe_free(compressed);


	/* =============== ServerHeader byte stream parsing ============ */

	ue_byte_stream_set_position(server_header_content_stream, 0);

	/* <packet_type_len> */
	if (!ue_byte_read_next_int(server_header_content_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <packet_type_len> field");
		goto clean_up;
	}
	pmsg->packet_type_len = (size_t)read_int;

	/* <source_nickname_len> */
	if (!ue_byte_read_next_int(server_header_content_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <source_nickname_len> field");
		goto clean_up;
	}
	pmsg->source_nickname_len = (size_t)read_int;

	/* <destination_nickname_len> */
	if (!ue_byte_read_next_int(server_header_content_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <destination_nickname_len> field");
		goto clean_up;
	}
	pmsg->destination_nickname_len = (size_t)read_int;

	/* <packet_type> */
	if (!ue_byte_read_next_bytes(server_header_content_stream, &pmsg->packet_type, pmsg->packet_type_len)) {
		ue_stacktrace_push_msg("Failed to parse <packet_type> field");
		goto clean_up;
	}

	/* <source_nickname> */
	if (!ue_byte_read_next_bytes(server_header_content_stream, &pmsg->source_nickname, pmsg->source_nickname_len)) {
		ue_stacktrace_push_msg("Failed to parse <source_nickname> field");
		goto clean_up;
	}

	/* <destination_nickname> */
	if (!ue_byte_read_next_bytes(server_header_content_stream, &pmsg->destination_nickname, pmsg->destination_nickname_len)) {
		ue_stacktrace_push_msg("Failed to parse <destination_nickname> field");
		goto clean_up;
	}

	succeed = true;

/* Clean-up resources */
clean_up:
	ue_safe_free(server_aes_key_tmp);
	ue_sym_key_destroy(server_aes_key);
	ue_safe_free(server_aes_iv);
	ue_safe_free(decompressed_len_uchar);
	ue_safe_free(compressed);
	ue_safe_free(decompressed);
	ue_byte_stream_destroy(server_header_stream);
	ue_byte_stream_destroy(server_header_content_stream);
	ue_byte_stream_destroy(key_header_stream);
	ue_safe_free(ciphered);
	ue_safe_free(key_header);
	ue_safe_free(server_content_field);
	ue_sym_encrypter_destroy(sencrypter);
	ue_asym_encrypter_destroy(asencrypter);
	return succeed;
}

static bool build_decrypted_receiver_header(ue_pgp_keystore_manager *manager, ue_pgp_keystore *keystore, ue_plain_message *pmsg, ue_cipher_message *cmsg) {
	bool succeed;
	unsigned char *receiver_aes_key_tmp, *receiver_aes_iv, *decompressed_len_uchar, *compressed, *decompressed,
		*receiver_content_field, *ciphered, *key_header;
	size_t decompressed_len, ciphered_len, key_header_len, compressed_len;
	int read_int, receiver_aes_key_tmp_len, deciphered_len,
		receiver_aes_iv_len, decompressed_len_uchar_len, receiver_content_field_len;
	ue_byte_stream *receiver_header_stream, *receiver_header_content_stream, *key_header_stream;
	ue_public_key *sender_pk;
	char *tmp_source_nickname, *hex;
	ue_asym_encrypter *asencrypter;
	ue_sym_encrypter *sencrypter;
	ue_sym_key *receiver_aes_key;

	succeed = false;
	receiver_aes_key = NULL;
	receiver_aes_key_tmp = NULL;
	receiver_aes_iv = NULL;
	decompressed_len_uchar = NULL;
	compressed = NULL;
	decompressed = NULL;
	receiver_header_stream = ue_byte_stream_create();
	receiver_header_content_stream = ue_byte_stream_create();
	key_header_stream = ue_byte_stream_create();
	sender_pk = NULL;
	tmp_source_nickname = NULL;
	receiver_content_field = NULL;
	ciphered = NULL;
	key_header = NULL;
	asencrypter = NULL;
	sencrypter = NULL;
	hex = NULL;
	deciphered_len = 0;

	/* ============ ReceiverHeader spliting ============ */

	if (!ue_byte_writer_append_bytes(receiver_header_stream, cmsg->receiver_header, cmsg->receiver_header_size)) {
		ue_stacktrace_push_msg("Failed to write ciphered raw message to receiver header stream");
		goto clean_up;
	}

	ue_byte_stream_set_position(receiver_header_stream, 0);

	if (!ue_byte_read_next_int(receiver_header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <ciphered_key_header_len> field");
		goto clean_up;
	}
	ciphered_len = read_int;

	/* <receiver_content_field_len> */
	if (!ue_byte_read_next_int(receiver_header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <receiver_content_field_len> field");
		goto clean_up;
	}
	receiver_content_field_len = (size_t)read_int;

	/* <key_header> */
	if (!ue_byte_read_next_bytes(receiver_header_stream, &ciphered, ciphered_len)) {
		ue_stacktrace_push_msg("Failed to parse <key_header> field");
		goto clean_up;
	}

	if (!ue_byte_read_next_bytes(receiver_header_stream, &receiver_content_field, (size_t)receiver_content_field_len)) {
		ue_stacktrace_push_msg("Failed to parse <receiver_content_field> field");
		goto clean_up;
	}

	/* =============================================== */



	/* ============ ReceiverHeader AES key field decryption ============ */

	asencrypter = ue_asym_encrypter_default_create(NULL, keystore->sk);

	if (!(key_header = ue_asym_encrypter_private_decrypt(asencrypter, ciphered, ciphered_len, &key_header_len))) {
		ue_stacktrace_push_msg("Failed to decrypt key header with our private key");
		goto clean_up;
	}

	if (!ue_byte_writer_append_bytes(key_header_stream, key_header, key_header_len)) {
		ue_stacktrace_push_msg("Failed to append key header");
		goto clean_up;
	}

	ue_byte_stream_set_position(key_header_stream, 0);

	// <receiver_aes_key_len>
	if (!ue_byte_read_next_int(key_header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <receiver_aes_key_len> field");
		goto clean_up;
	}
	receiver_aes_key_tmp_len = (size_t)read_int;

	// <receiver_aes_iv_len>
	if (!ue_byte_read_next_int(key_header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <receiver_aes_iv_len> field");
		goto clean_up;
	}
	receiver_aes_iv_len = (size_t)read_int;

	// <decompressed_len_uchar_len>
	if (!ue_byte_read_next_int(key_header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <decompressed_len_uchar_len> field");
		goto clean_up;
	}
	decompressed_len_uchar_len = (size_t)read_int;

	// <receiver_aes_key>
	if (!ue_byte_read_next_bytes(key_header_stream, &receiver_aes_key_tmp, receiver_aes_key_tmp_len)) {
		ue_stacktrace_push_msg("Failed to parse <receiver_aes_key> field");
		goto clean_up;
	}
	receiver_aes_key = ue_sym_key_create(receiver_aes_key_tmp, receiver_aes_key_tmp_len);

	// <receiver_aes_iv>
	if (!ue_byte_read_next_bytes(key_header_stream, &receiver_aes_iv, (size_t)receiver_aes_iv_len)) {
		ue_stacktrace_push_msg("Failed to parse <receiver_aes_iv> field");
		goto clean_up;
	}
	hex = ue_bytes_to_hex(receiver_aes_iv, receiver_aes_iv_len);
	ue_logger_trace("recovered receiver_aes_iv : %s", hex);
	ue_safe_free(hex);

	// <decompressed_len_uchar>
	if (!ue_byte_read_next_bytes(key_header_stream, &decompressed_len_uchar, (size_t)decompressed_len_uchar_len)) {
		ue_stacktrace_push_msg("Failed to parse <decompressed_len_uchar> field");
		goto clean_up;
	}

	/* =============================================================== */

	deciphered_len = ue_bytes_to_int(decompressed_len_uchar);
	ue_logger_trace("deciphered_len : %d", deciphered_len);

	/* =============== ReceiverHeader content field decryption ============ */

	/* Decrypt the fourth part with the previous AES key and IV */
	sencrypter = ue_sym_encrypter_default_create(receiver_aes_key);
	if (!(compressed = ue_sym_encrypter_decrypt(sencrypter, receiver_content_field, receiver_content_field_len, receiver_aes_iv, receiver_aes_iv_len, &compressed_len))) {
		ue_stacktrace_push_msg("Failed to decrypt ReceiverHeader content");
		goto clean_up;
	}

	ue_logger_trace("compressed_len : %ld", compressed_len);

	/* Decompress the fourth part with the previous known decompressed len */
	decompressed_len = (size_t)deciphered_len;
	if (!(decompressed = ue_decompress_buf(compressed, compressed_len, decompressed_len))) {
		ue_stacktrace_push_msg("Failed to decompress decryted ReceiverHeader");
		goto clean_up;
	}

	/* Fill a byte stream with the payload of ReceiverHeader */
	if (!ue_byte_writer_append_bytes(receiver_header_content_stream, decompressed, decompressed_len)) {
		ue_stacktrace_push_msg("Failed to append ReceiverHeader bytes to byte stream");
		goto clean_up;
	}

	ue_safe_free(compressed);
	ue_safe_free(decompressed);

	/* ================================================================== */



	/* =============== ReceiverHeader byte stream parsing ============ */

	ue_byte_stream_set_position(receiver_header_content_stream, 0);

	/* ReceiverHeaderLen */

	/* <packet_type_len> */
	if (!ue_byte_read_next_int(receiver_header_content_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <packet_type_len> field");
		goto clean_up;
	}
	pmsg->packet_type_len = (size_t)read_int;

	/* <source_nickname_len> */
	if (!ue_byte_read_next_int(receiver_header_content_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <source_nickname_len> field");
		goto clean_up;
	}
	pmsg->source_nickname_len = (size_t)read_int;

	/* <destination_nickname_len> */
	if (!ue_byte_read_next_int(receiver_header_content_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <destination_nickname_len> field");
		goto clean_up;
	}
	pmsg->destination_nickname_len = (size_t)read_int;

	/* <key_len> */
	if (!ue_byte_read_next_int(receiver_header_content_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <key_len> field");
		goto clean_up;
	}
	pmsg->key_len = (size_t)read_int;

	/* <iv_len> */
	if (!ue_byte_read_next_int(receiver_header_content_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <iv_len> field");
		goto clean_up;
	}
	pmsg->iv_len = (size_t)read_int;

	/* <content_len_uchar_size> */
	if (!ue_byte_read_next_int(receiver_header_content_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <content_len_uchar_size> field");
		goto clean_up;
	}
	pmsg->content_len_uchar_size = read_int;

	/* <signature_len> */
	if (!ue_byte_read_next_int(receiver_header_content_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <signature_len> field");
		goto clean_up;
	}
	pmsg->signature_len = read_int;

	/* ReceiverHeaderContent */

	/* <packet_type> */
	if (!ue_byte_read_next_bytes(receiver_header_content_stream, &pmsg->packet_type, pmsg->packet_type_len)) {
		ue_stacktrace_push_msg("Failed to parse <packet_type> field");
		goto clean_up;
	}

	/* <source_nickname> */
	if (!ue_byte_read_next_bytes(receiver_header_content_stream, &pmsg->source_nickname, pmsg->source_nickname_len)) {
		ue_stacktrace_push_msg("Failed to parse <source_nickname> field");
		goto clean_up;
	}

	/* <destination_nickname> */
	if (!ue_byte_read_next_bytes(receiver_header_content_stream, &pmsg->destination_nickname, pmsg->destination_nickname_len)) {
		ue_stacktrace_push_msg("Failed to parse <destination_nickname> field");
		goto clean_up;
	}

	/* <key> */
	if (!ue_byte_read_next_bytes(receiver_header_content_stream, &pmsg->key, pmsg->key_len)) {
		ue_stacktrace_push_msg("Failed to parse <key> field");
		goto clean_up;
	}

	/* <iv> */
	if (!ue_byte_read_next_bytes(receiver_header_content_stream, &pmsg->iv, pmsg->iv_len)) {
		ue_stacktrace_push_msg("Failed to parse <iv> field");
		goto clean_up;
	}

	/* <content_len_uchar> */
	if (!ue_byte_read_next_bytes(receiver_header_content_stream, &pmsg->content_len_uchar, pmsg->content_len_uchar_size)) {
		ue_stacktrace_push_msg("Failed to parse <content_len_uchar> field");
		goto clean_up;
	}

	/* <signature> */
	if (!ue_byte_read_next_bytes(receiver_header_content_stream, &pmsg->signature, (size_t)pmsg->signature_len)) {
		ue_stacktrace_push_msg("Failed to parse <signature> field");
		goto clean_up;
	}

	tmp_source_nickname = ue_string_create_from_bytes(pmsg->source_nickname, pmsg->source_nickname_len);
	if (!(sender_pk = ue_pgp_keystore_manager_get_pk_from_nickname(manager, tmp_source_nickname))) {
		ue_stacktrace_push_msg("Failed to get public key of sender");
		goto clean_up;
	}
	ue_safe_free(tmp_source_nickname);

	/* ============================================================= */

	succeed = true;

/* Clean-up resources */
clean_up:
	ue_sym_key_destroy(receiver_aes_key);
	ue_safe_free(receiver_aes_key_tmp);
	ue_safe_free(receiver_aes_iv);
	ue_safe_free(decompressed_len_uchar);
	ue_safe_free(compressed);
	ue_safe_free(decompressed);
	ue_byte_stream_destroy(receiver_header_stream);
	ue_byte_stream_destroy(receiver_header_content_stream);
	ue_byte_stream_destroy(key_header_stream);
	ue_safe_free(tmp_source_nickname);
	ue_safe_free(receiver_content_field);
	ue_safe_free(ciphered);
	ue_safe_free(key_header);
	ue_asym_encrypter_destroy(asencrypter);
	ue_sym_encrypter_destroy(sencrypter);
	return succeed;
}

static bool build_decrypted_content(ue_pgp_keystore_manager *manager, ue_pgp_keystore *keystore, ue_plain_message *pmsg, ue_cipher_message *cmsg) {
	bool succeed;
	unsigned char *compressed;
	size_t compressed_len;
	int n;
	ue_sym_encrypter *sencrypter;
	ue_public_key *sender_pk;
	char *tmp_source_nickname;
	ue_signer *s;

	succeed = false;
	compressed = NULL;
	sencrypter = NULL;
	sender_pk = NULL;
	tmp_source_nickname = NULL;
	s = NULL;
	sencrypter = NULL;

	sencrypter = ue_sym_encrypter_default_create(ue_sym_key_create(pmsg->key, pmsg->key_len));
	if (!(compressed = ue_sym_encrypter_decrypt(sencrypter, cmsg->content, cmsg->content_size, pmsg->iv, pmsg->iv_len, &compressed_len))) {
		ue_stacktrace_push_msg("Failed to decrypt message content");
		goto clean_up;
	}

	n = ue_bytes_to_int(pmsg->content_len_uchar);
	if (!(pmsg->content = ue_decompress_buf(compressed, compressed_len, n))) {
		ue_stacktrace_push_msg("Failed to compress ContentHeader content");
		goto clean_up;
	}
	pmsg->content_len = (size_t)n;

	tmp_source_nickname = ue_string_create_from_bytes(pmsg->source_nickname, pmsg->source_nickname_len);
	if (!(sender_pk = ue_pgp_keystore_manager_get_pk_from_nickname(manager, tmp_source_nickname))) {
		ue_stacktrace_push_msg("Failed to get public key of sender");
		goto clean_up;
	}
	ue_safe_free(tmp_source_nickname);

	s = ue_rsa_signer_create(sender_pk, NULL);

	if (!ue_signer_verify_buffer(s, pmsg->content, pmsg->content_len, pmsg->signature, pmsg->signature_len)) {
		ue_stacktrace_push_msg("Failed to verify the signature of the sender");
		goto clean_up;
	}

	succeed = true;

clean_up:
	ue_safe_free(compressed);
	ue_sym_encrypter_destroy_all(sencrypter);
	ue_signer_destroy_all(s);
	return succeed;
}

ue_plain_message *ue_message_build_decrypted_as_client(ue_pgp_keystore_manager *manager, ue_cipher_message *cmsg) {
	ue_plain_message *pmsg;
	ue_pgp_keystore *keystore;

	pmsg = ue_plain_message_create_empty();
	keystore = NULL;

	/* Get keystore */
	if (!(keystore = ue_pgp_keystore_manager_get_keystore(manager))) {
		ue_stacktrace_push_msg("Failed to get pgp keystore");
		goto failed;
	}

	if (!build_decrypted_receiver_header(manager, keystore, pmsg, cmsg)) {
		ue_stacktrace_push_msg("Failed to build decrypted ReceiverHeader field");
		goto failed;
	}

	if (!build_decrypted_content(manager, keystore, pmsg, cmsg)) {
		ue_stacktrace_push_msg("Failed to build decrypted Content field");
		goto failed;
	}

	return pmsg;

failed:
	ue_plain_message_destroy(pmsg);
	return NULL;
}

ue_plain_message *ue_message_build_decrypted_as_server(ue_pgp_keystore_manager *manager, ue_cipher_message *cmsg) {
	ue_plain_message *pmsg;
	ue_pgp_keystore *keystore;

	pmsg = ue_plain_message_create_empty();
	keystore = NULL;

	/* Get keystore */
	if (!(keystore = ue_pgp_keystore_manager_get_keystore(manager))) {
		ue_stacktrace_push_msg("Failed to get pgp keystore");
		goto clean_up;
	}

	if (!build_decrypted_server_header(keystore, pmsg, cmsg)) {
		ue_stacktrace_push_msg("Failed to build decrypted ServerHeader field");
		goto failed;
	}

clean_up:
	return pmsg;

failed:
	ue_plain_message_destroy(pmsg);
	return NULL;
}

ue_cipher_message *ue_data_to_cipher_message(unsigned char *message_content, size_t message_size) {
	ue_cipher_message *cmsg;
	ue_byte_stream *message_stream;
	int read_int;

	cmsg = NULL;
	message_stream = ue_byte_stream_create();

	ue_safe_alloc(cmsg, ue_cipher_message, 1);
	cmsg->server_header = NULL;
	cmsg->server_header_size = 0;
	cmsg->receiver_header = NULL;
	cmsg->receiver_header_size = 0;
	cmsg->content = NULL;
	cmsg->content_size = 0;

	if (!ue_byte_writer_append_bytes(message_stream, message_content, message_size)) {
		ue_stacktrace_push_msg("Failed to append message content to message stream");
		goto failed;
	}

	ue_byte_stream_set_position(message_stream, 0);

	/* <server_header_size> */
	if (!ue_byte_read_next_int(message_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <server_header_size> field");
		goto failed;
	}
	cmsg->server_header_size = (size_t)read_int;
	ue_logger_trace("cmsg->server_header_size : %ld", cmsg->server_header_size);

	/* <receiver_header_size> */
	if (!ue_byte_read_next_int(message_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <receiver_header_size> field");
		goto failed;
	}
	cmsg->receiver_header_size = (size_t)read_int;
	ue_logger_trace("cmsg->receiver_header_size : %ld", cmsg->receiver_header_size);

	/* <content_size> */
	if (!ue_byte_read_next_int(message_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <content_size> field");
		goto failed;
	}
	cmsg->content_size = (size_t)read_int;
	ue_logger_trace("cmsg->content_size : %ld", cmsg->content_size);

	if (!ue_byte_read_next_bytes(message_stream, &cmsg->server_header, cmsg->server_header_size)) {
		ue_stacktrace_push_msg("Failed to parse <server_header> field");
		goto failed;
	}

	if (!ue_byte_read_next_bytes(message_stream, &cmsg->receiver_header, cmsg->receiver_header_size)) {
		ue_stacktrace_push_msg("Failed to parse <receiver_header> field");
		goto failed;
	}

	if (!ue_byte_read_next_bytes(message_stream, &cmsg->content, cmsg->content_size)) {
		ue_stacktrace_push_msg("Failed to parse <content> field");
		goto clean_up;
	}

clean_up:
	ue_byte_stream_destroy(message_stream);
	return cmsg;
failed:
	ue_cipher_message_destroy(cmsg);
	cmsg = NULL;
	goto clean_up;
}
