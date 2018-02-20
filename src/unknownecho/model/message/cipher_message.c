#include <unknownecho/model/message/cipher_message.h>
#include <unknownecho/model/message/plain_message.h>
#include <unknownecho/model/entity/pgp_keystore.h>
#include <unknownecho/model/manager/pgp_keystore_manager.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/crypto/api/encryption/asym_encrypter.h>
#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/api/compression/compress.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/crypto/factory/asym_encrypter_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
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

#include <string.h>

/**
 * This function is called in ue_message_build_encrypted_as_client() to encrypt ServerHeader
 * from datas of pmsg to cmsg.
 *
 * @author   Swaxxx
 * @version  1.0
 * @param    manager  the keystore manager to acceed to server public key
 * @param    keystore the keystore to acceed to our private key
 * @param    pmsg  the plaintext message that contains all uncrypted datas
 * @param    cmsg  the cipher message where the ciphered server header will be wrote
 * @return   true if ServerHeader is successfully encrypted to cmsg, false otherwise
 * @see  	 ue_cipher_message_struct
 * @see  	 ue_plain_message_struct
 * @see      ue_message_build_encrypted_as_client
 * @date     Christmas 2017
 *
 * @format
 *
 * Build ServerHeader as
 * ServerHeader = Len(RSA_public_encrypt(server.pub, <server_aes_key>)) +
 *	  Len(RSA_public_encrypt(server.pub, <server_aes_iv>)) +
 *	  Len(RSA_public_encrypt(server.pub, <Len(<ServerHeaderLen> + <ServerHeaderContent>)) +
 *	  Len(AES-CBC(<server_aes_key>, <server_iv_key>, DeflateCompress(<ServerHeaderLen> + <ServerHeaderContent>))) +
 *	  RSA_public_encrypt(server.pub, <server_aes_key>) +
 *    RSA_public_encrypt(server.pub, <server_aes_iv>) +
 *    RSA_public_encrypt(server.pub, <Len(<ServerHeaderLen> + <ServerHeaderContent>)) +
 *	  AES-CBC(<server_aes_key>, <server_iv_key>, DeflateCompress(<ServerHeaderLen> + <ServerHeaderContent>));
 *
 * ServerHeaderLen = <packet_type_len> + <destination_nickname_len>
 *
 * ServerHeaderContent = <packet_type> + <destination_nickname>
 */
static bool build_encrypted_server_header(ue_pgp_keystore_manager *manager, ue_pgp_keystore *keystore, ue_plain_message *pmsg, ue_cipher_message *cmsg) {
	bool succeed;
	ue_byte_stream *server_header_stream, *server_header_content_stream, *key_header_stream;
	unsigned char *server_aes_iv, *ciphered, *compressed, *decompressed_len_uchar,
		*key_header, *server_content_field;
	size_t server_aes_iv_len, decompressed_len_uchar_size, compressed_len, key_header_len, server_content_field_len;
	ue_sym_encrypter *sencrypter;
	ue_sym_key *server_aes_key;
	ue_asym_encrypter *asencrypter;

	succeed = false;
	server_header_stream = ue_byte_stream_create();
	server_header_content_stream = ue_byte_stream_create();
	key_header_stream = ue_byte_stream_create();
	server_aes_key = NULL;
	server_aes_iv = NULL;
	ciphered = NULL;
	compressed = NULL;
	decompressed_len_uchar = NULL;
	server_content_field = NULL;
	key_header = NULL;
	sencrypter = NULL;
	asencrypter = NULL;

	/* Fill stream with ServerHeaderLen and ServerHeader */
	if (!(ue_byte_writer_append_int(server_header_content_stream, (int)pmsg->packet_type_len))) {
		ue_stacktrace_push_msg("Failed to append <packet_type_len> field to ServerHeader content stream");
		goto clean_up;
	}
	if (!(ue_byte_writer_append_int(server_header_content_stream, (int)pmsg->source_nickname_len))) {
		ue_stacktrace_push_msg("Failed to append <source_nickname_len> field to ServerHeader content stream");
		goto clean_up;
	}
	if (!(ue_byte_writer_append_int(server_header_content_stream, (int)pmsg->destination_nickname_len))) {
		ue_stacktrace_push_msg("Failed to append <destination_nickname_len> field to ServerHeader content stream");
		goto clean_up;
	}
	if (!(ue_byte_writer_append_bytes(server_header_content_stream, pmsg->packet_type, pmsg->packet_type_len))) {
		ue_stacktrace_push_msg("Failed to append <packet_type> field to ServerHeader content stream");
		goto clean_up;
	}
	if (!(ue_byte_writer_append_bytes(server_header_content_stream, pmsg->source_nickname, pmsg->source_nickname_len))) {
		ue_stacktrace_push_msg("Failed to append <source_nickname> field to ServerHeader content stream");
		goto clean_up;
	}
	if (!(ue_byte_writer_append_bytes(server_header_content_stream, pmsg->destination_nickname, pmsg->destination_nickname_len))) {
		ue_stacktrace_push_msg("Failed to append <destination_nickname> field to ServerHeader content stream");
		goto clean_up;
	}

	/* ============ ServerHeader AES key field encryption ============ */

	/* Generate random aes key for server header encryption */
	if (!(server_aes_key = ue_sym_key_create_random())) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for server aes key generation");
		goto clean_up;
	}

	/* ============ ServerHeader AES IV field encryption ============ */

	/* Generate random aes IV for server header encryption */
	server_aes_iv_len = 16;
	ue_safe_alloc(server_aes_iv, unsigned char, server_aes_iv_len);
	if (!(ue_crypto_random_bytes(server_aes_iv, server_aes_iv_len))) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for server aes iv generation");
		goto clean_up;
	}


	/* ============ ServerHeader decompressed len field encryption ============ */

	/* DeflateDecompress algorithm needs the plaintext size to proceed */
	decompressed_len_uchar_size = 4;
	ue_safe_alloc(decompressed_len_uchar, unsigned char, decompressed_len_uchar_size);
	ue_int_to_bytes(ue_byte_stream_get_size(server_header_content_stream), decompressed_len_uchar);

	if (!(ue_byte_writer_append_int(key_header_stream, (int)server_aes_key->size))) {
		ue_stacktrace_push_msg("Failed to append <server_aes_key_len> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_int(key_header_stream, (int)server_aes_iv_len))) {
		ue_stacktrace_push_msg("Failed to append <server_aes_iv_len> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_int(key_header_stream, (int)decompressed_len_uchar_size))) {
		ue_stacktrace_push_msg("Failed to append <decompressed_len_uchar_size> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(key_header_stream, server_aes_key->data, server_aes_key->size))) {
		ue_stacktrace_push_msg("Failed to append <server_aes_key> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(key_header_stream, server_aes_iv, server_aes_iv_len))) {
		ue_stacktrace_push_msg("Failed to append <server_aes_iv> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(key_header_stream, decompressed_len_uchar, decompressed_len_uchar_size))) {
		ue_stacktrace_push_msg("Failed to append <decompressed_len_uchar> field to key header stream");
		goto clean_up;
	}



	/* ============ Encrypt content key/iv/plaintext len with server pk ============ */

	//asencrypter = ue_asym_encrypter_default_create(keystore->akey);
	asencrypter = ue_asym_encrypter_default_create(keystore->server_pk, NULL);

	if (!(key_header = ue_asym_encrypter_public_encrypt(asencrypter, ue_byte_stream_get_data(key_header_stream),
		ue_byte_stream_get_size(key_header_stream), &key_header_len))) {
		ue_stacktrace_push_msg("Failed to encrypt server aes iv with server public key");
		goto clean_up;
	}

	/* =============== ServerHeader content field encryption ============ */

	/* Compress ServerHeaderContent */
	if (!(compressed = ue_compress_buf(ue_byte_stream_get_data(server_header_content_stream), ue_byte_stream_get_size(server_header_content_stream), &compressed_len))) {
		ue_stacktrace_push_msg("Failed to compress ServerHeader content");
		goto clean_up;
	}

	/* Encrypt the compressed ServerHeaderContent with AES key */
	sencrypter = ue_sym_encrypter_default_create(server_aes_key);
	if (!(server_content_field = ue_sym_encrypter_encrypt(sencrypter, compressed, compressed_len, server_aes_iv, server_aes_iv_len, &server_content_field_len))) {
		ue_stacktrace_push_msg("Failed to encrypt ServerHeader content");
		goto clean_up;
	}

	/* =============== Append all fields in final ServerHeader stream ============ */

	if (!(ue_byte_writer_append_int(server_header_stream, key_header_len))) {
		ue_stacktrace_push_msg("Failed to append field <key_header_len> to ServerHeader stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_int(server_header_stream, (int)server_content_field_len))) {
		ue_stacktrace_push_msg("Failed to append field <server_content_field_len> to ServerHeader stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(server_header_stream, key_header, key_header_len))) {
		ue_stacktrace_push_msg("Failed to append field <key_header> to ServerHeader stream");
		goto clean_up;
	}

	char *hex = ue_bytes_to_hex(key_header, key_header_len);
	ue_logger_trace("Key header server : %s", hex);
	ue_safe_free(hex);

	if (!(ue_byte_writer_append_bytes(server_header_stream, server_content_field, server_content_field_len))) {
		ue_stacktrace_push_msg("Failed to append field <server_content_field> to ServerHeader stream");
		goto clean_up;
	}


	/* Write the ServerHeader to the ciphered message structure from the byte stream */
	if (!(cmsg->server_header = ue_bytes_create_from_bytes(ue_byte_stream_get_data(server_header_stream), ue_byte_stream_get_size(server_header_stream)))) {
		ue_stacktrace_push_msg("Failed to copy server header byte stream to server header field");
		goto clean_up;
	}

	cmsg->server_header_size = ue_byte_stream_get_size(server_header_stream);

	succeed = true;

/* Clean-up resources */
clean_up:
	ue_byte_stream_destroy(server_header_content_stream);
	ue_byte_stream_destroy(server_header_stream);
	ue_byte_stream_destroy(key_header_stream);
	ue_sym_key_destroy(server_aes_key);
	ue_safe_free(server_aes_iv);
	ue_safe_free(ciphered);
	ue_safe_free(compressed);
	ue_safe_free(decompressed_len_uchar);
	ue_safe_free(server_content_field);
	ue_safe_free(key_header);
	ue_sym_encrypter_destroy(sencrypter);
	ue_asym_encrypter_destroy(asencrypter);
	return succeed;
}

/**
 * This function is called in ue_message_build_encrypted_as_client() to encrypt ReceiverHeader
 * from datas of pmsg to cmsg.
 *
 * @author   Swaxxx
 * @version  1.0
 * @param    manager  the keystore manager to acceed to receiver public key
 * @param    keystore the keystore to acceed to our private key
 * @param    pmsg  the plaintext message that contains all uncrypted datas
 * @param    cmsg  the cipher message where the ciphered receiver header will be wrote
 * @return   true if ReceiverHeader is successfully encrypted to cmsg, false otherwise
 * @see  	 ue_cipher_message_struct
 * @see  	 ue_plain_message_struct
 * @see      ue_message_build_encrypted_as_client
 * @date     Christmas 2017
 *
 * @format
 *
 * Build ReceiverHeader as
 * ReceiverHeader = Len(RSA_public_encrypt(receiver.pub, <receiver_aes_key>)) +
 *	  Len(RSA_public_encrypt(receiver.pub, <receiver_aes_iv>)) +
 *	  Len(RSA_public_encrypt(receiver.pub, <Len(<ReceiverHeaderLen> + <ReceiverHeaderContent>))) +
 *    Len(AES-CBC(<receiver_aes_key>, <receiver_aes_iv>, DeflateCompress(<ReceiverHeaderLen> + <ReceiverHeaderContent>))) +
 *	  RSA_public_encrypt(receiver.pub, <receiver_aes_key>) +
 *    RSA_public_encrypt(receiver.pub, <receiver_aes_iv>) +
 *    RSA_public_encrypt(receiver.pub, <Len(<ReceiverHeaderLen> + <ReceiverHeaderContent>)) +
 *	  AES-CBC(<receiver_aes_key>, <receiver_aes_iv>, DeflateCompress(<ReceiverHeaderLen> + <ReceiverHeaderContent>));
 *
 * Build ReceiverHeaderLen
 * ReceiverHeaderLen = <packet_type_len> + <source_nickname_len> + <destination_nickname_len> +
 *    <content_aes_key_len> + <content_aes_iv_len> + <content_len_len> + <signature_len>
 *
 * ReceiverHeaderContent = <packet_type> + <source_nickname> + <destination_nickname> +
 *    <content_aes_key> + <content_aes_iv> + <content_len> + <signature>
 *
 * with <signature> = RSA_private_encrypt(sender.priv, SHA256(<content>));
 */
static bool build_encrypted_receiver_header(ue_pgp_keystore_manager *manager, ue_pgp_keystore *keystore, ue_plain_message *pmsg, ue_cipher_message *cmsg) {
	bool succeed;
	ue_public_key *receiver_pk;
	char *nickname, *hex;
	unsigned char *receiver_aes_iv, *ciphered, *decompressed_len_uchar, *compressed,
		*receiver_aes_key_field, *receiver_aes_iv_field, *receiver_content_field, *key_header;
	size_t receiver_aes_iv_len, decompressed_len_uchar_size, compressed_len, key_header_len,
		receiver_content_field_len;
	ue_byte_stream *receiver_header_content_stream, *receiver_header_stream, *key_header_stream;
	ue_sym_encrypter *sencrypter;
	ue_sym_key *receiver_aes_key;
	ue_asym_encrypter *asencrypter;

	succeed = false;
	receiver_pk = NULL;
	nickname = NULL;
	receiver_aes_key = NULL;
	receiver_aes_iv = NULL;
	key_header = NULL;
	receiver_header_content_stream = ue_byte_stream_create();
	receiver_header_stream = ue_byte_stream_create();
	key_header_stream = ue_byte_stream_create();
	ciphered = NULL;
	decompressed_len_uchar = NULL;
	compressed = NULL;
	receiver_aes_key_field = NULL;
	receiver_aes_iv_field = NULL;
	receiver_content_field = NULL;
	hex = NULL;
	asencrypter = NULL;
	sencrypter = NULL;

	/* Get the public key of the receiver from the destination nickname */
	nickname = ue_string_create_from_bytes(pmsg->destination_nickname, pmsg->destination_nickname_len);
	if (!(receiver_pk = ue_pgp_keystore_manager_get_pk_from_nickname(manager, nickname))) {
		ue_stacktrace_push_msg("Failed to get public key of receiver");
		goto clean_up;
	}

	/* Generate random aes key for receiver header encryption */
	if (!(receiver_aes_key = ue_sym_key_create_random())) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for receiver aes key generation");
		goto clean_up;
	}

	/* Generate random aes IV for receiver header encryption */
	receiver_aes_iv_len = 16;
	ue_safe_alloc(receiver_aes_iv, unsigned char, receiver_aes_iv_len);
	if (!(ue_crypto_random_bytes(receiver_aes_iv, receiver_aes_iv_len))) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for receiver aes iv generation");
		goto clean_up;
	}

	/* ============ Fill the content of each field of ReceiverHeader ============ */

	/* ReceiverHeaderLen */

	/* <packet_type_len> */
	if (!(ue_byte_writer_append_int(receiver_header_content_stream, (int)pmsg->packet_type_len))) {
		ue_stacktrace_push_msg("Failed to append <packet_type_len> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <source_nickname_len> */
	if (!(ue_byte_writer_append_int(receiver_header_content_stream, (int)pmsg->source_nickname_len))) {
		ue_stacktrace_push_msg("Failed to append <source_nickname_len> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <destination_nickname_len> */
	if (!(ue_byte_writer_append_int(receiver_header_content_stream, (int)pmsg->destination_nickname_len))) {
		ue_stacktrace_push_msg("Failed to append <destination_nickname_len> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <key_len> */
	if (!(ue_byte_writer_append_int(receiver_header_content_stream, (int)pmsg->key_len))) {
		ue_stacktrace_push_msg("Failed to append <key_len> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <iv_len> */
	if (!(ue_byte_writer_append_int(receiver_header_content_stream, (int)pmsg->iv_len))) {
		ue_stacktrace_push_msg("Failed to append <iv_len> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <content_len_len> */
	if (!(ue_byte_writer_append_int(receiver_header_content_stream, 4))) {
		ue_stacktrace_push_msg("Failed to append <content_len_len> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <signature_len> */
	if (!(ue_byte_writer_append_int(receiver_header_content_stream, pmsg->signature_len))) {
		ue_stacktrace_push_msg("Failed to append <signature_len> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* ReceiverHeaderContent */

	/* <packet_type> */
	if (!(ue_byte_writer_append_bytes(receiver_header_content_stream, pmsg->packet_type, pmsg->packet_type_len))) {
		ue_stacktrace_push_msg("Failed to append <packet_type> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <source_nickname> */
	if (!(ue_byte_writer_append_bytes(receiver_header_content_stream, pmsg->source_nickname, pmsg->source_nickname_len))) {
		ue_stacktrace_push_msg("Failed to append <source_nickname> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <destination_nickname> */
	if (!(ue_byte_writer_append_bytes(receiver_header_content_stream, pmsg->destination_nickname, pmsg->destination_nickname_len))) {
		ue_stacktrace_push_msg("Failed to append <destination_nickname> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <key> */
	if (!(ue_byte_writer_append_bytes(receiver_header_content_stream, pmsg->key, pmsg->key_len))) {
		ue_stacktrace_push_msg("Failed to append <key> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <iv> */
	if (!(ue_byte_writer_append_bytes(receiver_header_content_stream, pmsg->iv, pmsg->iv_len))) {
		ue_stacktrace_push_msg("Failed to append <iv> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <content_len> */
	if (!(ue_byte_writer_append_int(receiver_header_content_stream, (int)pmsg->content_len))) {
		ue_stacktrace_push_msg("Failed to append <content_len> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* <signature> */
	if (!(ue_byte_writer_append_bytes(receiver_header_content_stream, pmsg->signature, (size_t)pmsg->signature_len))) {
		ue_stacktrace_push_msg("Failed to append <signature> field to ReceiverHeader content stream");
		goto clean_up;
	}

	/* ========================================================================== */

	/* DeflateDecompress algorithm needs the plaintext size to proceed */
	decompressed_len_uchar_size = 4;
	ue_safe_alloc(decompressed_len_uchar, unsigned char, decompressed_len_uchar_size);
	ue_int_to_bytes(ue_byte_stream_get_size(receiver_header_content_stream), decompressed_len_uchar);
	ue_logger_trace("ue_byte_stream_get_size(receiver_header_content_stream) : %ld", ue_byte_stream_get_size(receiver_header_content_stream));

	/* ============ Fill the receiver key header stream ============ */

	if (!(ue_byte_writer_append_int(key_header_stream, (int)receiver_aes_key->size))) {
		ue_stacktrace_push_msg("Failed to append <receiver_aes_key_len> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_int(key_header_stream, (int)receiver_aes_iv_len))) {
		ue_stacktrace_push_msg("Failed to append <receiver_aes_iv_len> field to key header stream");
		goto clean_up;
	}

	hex = ue_bytes_to_hex(receiver_aes_iv, receiver_aes_iv_len);
	ue_logger_trace("receiver_aes_iv : %s", hex);
	ue_safe_free(hex);

	if (!(ue_byte_writer_append_int(key_header_stream, (int)decompressed_len_uchar_size))) {
		ue_stacktrace_push_msg("Failed to append <decompressed_len_uchar_size> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(key_header_stream, receiver_aes_key->data, receiver_aes_key->size))) {
		ue_stacktrace_push_msg("Failed to append <receiver_aes_key> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(key_header_stream, receiver_aes_iv, receiver_aes_iv_len))) {
		ue_stacktrace_push_msg("Failed to append <receiver_aes_iv> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(key_header_stream, decompressed_len_uchar, decompressed_len_uchar_size))) {
		ue_stacktrace_push_msg("Failed to append <decompressed_len_uchar> field to key header stream");
		goto clean_up;
	}

	/* ============================================================= */



	/* ============ Encrypt content key/iv/plaintext len with receiver pk ============ */

	asencrypter = ue_asym_encrypter_default_create(receiver_pk, NULL);

	if (!(key_header = ue_asym_encrypter_public_encrypt(asencrypter, ue_byte_stream_get_data(key_header_stream),
		ue_byte_stream_get_size(key_header_stream), &key_header_len))) {
		ue_stacktrace_push_msg("Failed to encrypt receiver aes iv with receiver public key");
		goto clean_up;
	}

	/* =============================================================================== */



	/* =============== ReceiverHeader content field encryption ============ */

	if (!(compressed = ue_compress_buf(ue_byte_stream_get_data(receiver_header_content_stream), ue_byte_stream_get_size(receiver_header_content_stream), &compressed_len))) {
		ue_stacktrace_push_msg("Failed to compress ReceiverHeader content");
		goto clean_up;
	}

	ue_logger_trace("compressed_len : %ld", compressed_len);

	sencrypter = ue_sym_encrypter_default_create(receiver_aes_key);
	if (!(receiver_content_field = ue_sym_encrypter_encrypt(sencrypter, compressed, compressed_len, receiver_aes_iv, receiver_aes_iv_len, &receiver_content_field_len))) {
		ue_stacktrace_push_msg("Failed to encrypt ReceiverHeader content");
		goto clean_up;
	}

	/* ==================================================================== */



	/* =============== Append all fields in final ReceiverHeader stream ============ */

	if (!(ue_byte_writer_append_int(receiver_header_stream, (int)key_header_len))) {
		ue_stacktrace_push_msg("Failed to append field <key_header_len> to ReceiverHeader stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_int(receiver_header_stream, (int)receiver_content_field_len))) {
		ue_stacktrace_push_msg("Failed to append field <receiver_content_field_len> to ReceiverHeader stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(receiver_header_stream, key_header, key_header_len))) {
		ue_stacktrace_push_msg("Failed to append field <key_header> to ReceiverHeader stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(receiver_header_stream, receiver_content_field, receiver_content_field_len))) {
		ue_stacktrace_push_msg("Failed to append field <receiver_content_field> to ReceiverHeader stream");
		goto clean_up;
	}

	/* ============================================================================= */

	/* Write the ServerHeader to the ciphered message structure from the byte stream */
	if (!(cmsg->receiver_header = ue_bytes_create_from_bytes(ue_byte_stream_get_data(receiver_header_stream), ue_byte_stream_get_size(receiver_header_stream)))) {
		ue_stacktrace_push_msg("Failed to append to cipher message receiver header field the content of receiver header stream");
		goto clean_up;
	}

	cmsg->receiver_header_size = ue_byte_stream_get_size(receiver_header_stream);

	succeed = true;

/* Clean-up resources */
clean_up:
	ue_safe_free(nickname);
	ue_safe_free(receiver_aes_iv);
	ue_byte_stream_destroy(receiver_header_content_stream);
	ue_byte_stream_destroy(receiver_header_stream);
	ue_byte_stream_destroy(key_header_stream);
	ue_safe_free(ciphered);
	ue_safe_free(decompressed_len_uchar);
	ue_safe_free(compressed);
	ue_safe_free(receiver_aes_key_field);
	ue_safe_free(receiver_aes_iv_field);
	ue_safe_free(receiver_content_field);
	ue_safe_free(key_header);
	ue_sym_encrypter_destroy(sencrypter);
	ue_asym_encrypter_destroy(asencrypter);
	ue_sym_key_destroy(receiver_aes_key);
	return succeed;
}

/**
 * This function is called in ue_message_build_encrypted_as_client() to encrypt Content
 * from datas of pmsg to cmsg.
 *
 * @author   Swaxxx
 * @version  1.0
 * @param    pmsg  the plaintext message that contains all uncrypted datas
 * @param    cmsg  the cipher message where the ciphered content will be wrote
 * @return   true if Content is successfully encrypted to cmsg, false otherwise
 * @see  	 ue_cipher_message_struct
 * @see  	 ue_plain_message_struct
 * @see      ue_message_build_encrypted_as_client
 * @date     Christmas 2017
 *
 * @algorithm
 *
 * Content = AES-CBC(<key>, DeflateCompress(<content>));
 */
static bool build_encrypted_content(ue_plain_message *pmsg, ue_cipher_message *cmsg) {
	bool succeed;
	unsigned char *compressed;
	size_t compressed_len;
	ue_sym_encrypter *sencrypter;

	succeed = false;
	compressed = NULL;
	sencrypter = NULL;

	if (!(compressed = ue_compress_buf(pmsg->content, pmsg->content_len, &compressed_len))) {
		ue_stacktrace_push_msg("Failed to compress ContentHeader content");
		goto clean_up;
	}

	sencrypter = ue_sym_encrypter_default_create(ue_sym_key_create(pmsg->key, pmsg->key_len));

	cmsg->content = ue_sym_encrypter_encrypt(sencrypter, compressed, compressed_len, pmsg->iv, pmsg->iv_len, &cmsg->content_size);

	succeed = true;

clean_up:
	ue_safe_free(compressed);
	ue_sym_encrypter_destroy_all(sencrypter);
	return succeed;
}

/**
 * @author   Swaxxx
 * @version  1.0
 * @param    manager  the keystore manager to acceed to server public key
 * @param    pmsg  the plaintext message that contains all uncrypted datas
 * @return   cmsg  allocated if function succeed, NULL otherwise
 * @see  	 ue_cipher_message_struct
 * @see  	 ue_plain_message_struct
 * @see      build_encrypted_server_header
 * @see      build_encrypted_receiver_header
 * @see      build_encrypted_content
 * @date     Christmas 2017
 * @todo     desalocate each data soon as possible
 * @todo     add logging
 *
 * @algorithm
 *
 * M = ServerHeaderLen + ReceiverHeaderLen + ContentLen + ServerHeader + ReceiverHeader + Content
 */
ue_cipher_message *ue_message_build_encrypted_as_client(ue_pgp_keystore_manager *manager, ue_plain_message *pmsg) {
	ue_cipher_message *cmsg;
	ue_pgp_keystore *keystore;

	cmsg = NULL;
	keystore = NULL;

	/* Get keystore  */
	if (!(keystore = ue_pgp_keystore_manager_get_keystore(manager))) {
		ue_stacktrace_push_msg("Failed to get pgp keystore");
		goto failed;
	}

	/* Allocate an empty message */
	ue_safe_alloc(cmsg, ue_cipher_message, 1);
	cmsg->server_header = NULL;
	cmsg->receiver_header = NULL;
	cmsg->content = NULL;

	/* Build the encrypted the ServerHeader */
	if (!build_encrypted_server_header(manager, keystore, pmsg, cmsg)) {
		ue_stacktrace_push_msg("Failed to encrypt ServerHeader");
		goto failed;
	}

	/* Build the encrypted ReceiverHeader */
	if (!build_encrypted_receiver_header(manager, keystore, pmsg, cmsg)) {
		ue_stacktrace_push_msg("Failed to encrypt ReceiverHeader");
		goto failed;
	}

	/* Build the encrypted Content */
	if (!build_encrypted_content(pmsg, cmsg)) {
		ue_stacktrace_push_msg("Failed to encrypt Content");
		goto failed;
	}

clean_up:
	return cmsg;

failed:
	ue_cipher_message_destroy(cmsg);
	cmsg = NULL;
	goto clean_up;
}

unsigned char *ue_cipher_message_to_data(ue_cipher_message *cmsg, size_t *message_size) {
	ue_byte_stream *message_stream;
	unsigned char *data;

	ue_check_parameter_or_return(cmsg->server_header);
	ue_check_parameter_or_return(cmsg->receiver_header);
	ue_check_parameter_or_return(cmsg->content);

	data = NULL;

	if (!(message_stream = ue_byte_stream_create())) {
		ue_stacktrace_push_msg("Failed to create empty byte stream for message");
		goto failed;
	}

	if (!(ue_byte_writer_append_int(message_stream, (int)cmsg->server_header_size))) {
		ue_stacktrace_push_msg("Failed to append field <server_header_size> of ue_cipher_message to message stream");
		goto clean_up;
	}
	ue_logger_trace("cmsg->server_header_size : %ld", cmsg->server_header_size);

	if (!(ue_byte_writer_append_int(message_stream, (int)cmsg->receiver_header_size))) {
		ue_stacktrace_push_msg("Failed to append field <receiver_header_size> of ue_cipher_message to message stream");
		goto clean_up;
	}
	ue_logger_trace("cmsg->receiver_header_size : %ld", cmsg->receiver_header_size);

	if (!(ue_byte_writer_append_int(message_stream, (int)cmsg->content_size))) {
		ue_stacktrace_push_msg("Failed to append field <content_size> of ue_cipher_message to message stream");
		goto clean_up;
	}
	ue_logger_trace("cmsg->content_size : %ld", cmsg->content_size);

	if (!(ue_byte_writer_append_bytes(message_stream, cmsg->server_header, cmsg->server_header_size))) {
		ue_stacktrace_push_msg("Failed to append field <server_header> of ue_cipher_message to message stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(message_stream, cmsg->receiver_header, cmsg->receiver_header_size))) {
		ue_stacktrace_push_msg("Failed to append field <receiver_header> of ue_cipher_message to message stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(message_stream, cmsg->content, cmsg->content_size))) {
		ue_stacktrace_push_msg("Failed to append field <content> of ue_cipher_message to message stream");
		goto clean_up;
	}

	if (!(*message_size = ue_byte_stream_get_size(message_stream))) {
		ue_stacktrace_push_msg("The message stream size is < 0 (this should never happened)");
		goto failed;
	}
	if (!(data = ue_bytes_create_from_bytes(ue_byte_stream_get_data(message_stream), *message_size))) {
		ue_stacktrace_push_msg("The message stream content is empty (this should never happened)");
		goto failed;
	}

clean_up:
	ue_byte_stream_destroy(message_stream);
	return data;

failed:
	ue_safe_free(data);
	data = NULL;
	goto clean_up;
}

void ue_cipher_message_destroy(ue_cipher_message *cmsg) {
	if (cmsg) {
		ue_safe_free(cmsg->server_header);
		ue_safe_free(cmsg->receiver_header);
		ue_safe_free(cmsg->content);
		ue_safe_free(cmsg);
	}
}

void ue_cipher_message_clean_up(ue_cipher_message *cmsg) {
	if (cmsg) {
		ue_safe_free(cmsg->server_header);
		ue_safe_free(cmsg->receiver_header);
		ue_safe_free(cmsg->content);
	}
}
