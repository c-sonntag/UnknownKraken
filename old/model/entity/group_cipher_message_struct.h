#ifndef UNKNOWNECHO_GROUP_CIPHER_MESSAGE_STRUCT_H
#define UNKNOWNECHO_GROUP_CIPHER_MESSAGE_STRUCT_H

#include <stddef.h>

/**
 * M = ServerHeader + '\n' + ReceiverHeader + '\n' + Content
 */
typedef struct {
	/**
	 * ServerHeader = Base64Encode(RSA_public_encrypt(server.pub, ServerHeaderLen + ServerHeaderContent))
	 *
	 * ServerHeaderLen = <packet_type_len> + <destination_nickname_len>
	 *
	 * ServerHeaderContent = <packet_type> + <destination_nickname>
	 */
	unsigned char *server_header;
	size_t server_header_size;

	/**
	 * ReceiverHeader = Base64Encode(AES-CBC(<session_key>, ReceiverHeaderLen + ReceiverHeaderContent))
	 *
	 * ReceiverHeaderLen = <source_nickname_len> + <digest_len> + <key_len> +
	 *    <optional_enc_data_len_1> + <optional_enc_data_len_2> + <optional_enc_data_len_3> +
	 *	  <optional_enc_data_len_4> + <content_len>
	 *
	 * ReceiverHeaderContent = <source_nickname> +
	 *    RSA_private_encrypt(sender.priv, SHA256(<content>)) + <key> +
	 *    <optional_enc_data_1> + <optional_enc_data_2> +
	 *    <optional_enc_data_3> + <optional_enc_data_4>) +
	 */
	unsigned char *receiver_header;
	size_t receiver_header_size;

	/* Content = Base64Encode(AES-CBC(<key>, DeflateCompress(<content>))) */
	unsigned char *content;
	size_t content_size;
} ue_group_cipher_message;

#endif
