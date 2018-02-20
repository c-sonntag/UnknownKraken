#ifndef UNKNOWNECHO_CIPHER_MESSAGE_STRUCT_H
#define UNKNOWNECHO_CIPHER_MESSAGE_STRUCT_H

#include <stddef.h>

/**
 * M = Len(ServerHeader) + Len(ReceiverHeader) + Len(Content) + ServerHeader + ReceiverHeader + Content
 */
typedef struct {
	/**
	 * ServerHeader = RSA_public_encrypt(server.pub, <server_aes_key>) +
	 *    RSA_public_encrypt(server.pub, <server_aes_iv>) +
	 *	  RSA_public_encrypt(server.pub, <Len(<ServerHeaderLen> + <ServerHeaderContent>)) +
	 *	  AES-CBC(<server_aes_key>, <server_iv_key>, DeflateCompress(<ServerHeaderLen> + <ServerHeaderContent>))
	 *
	 * ServerHeaderLen = <packet_type_len> + <destination_nickname_len>
	 *
	 * ServerHeaderContent = <packet_type> + <destination_nickname>
	 */
	unsigned char *server_header;
	size_t server_header_size;

	/**
	 * ReceiverHeader = RSA_public_encrypt(receiver.pub, <receiver_aes_key>) +
	 *    RSA_public_encrypt(receiver.pub, <receiver_aes_iv>) +
	 *	  RSA_public_encrypt(receiver.pub, <Len(<ReceiverHeaderLen> + <ReceiverHeaderContent>)) +
	 *	  AES-CBC(<receiver_aes_key>, <receiver_aes_iv>, DeflateCompress(<ReceiverHeaderLen> + <ReceiverHeaderContent>))
	 *
	 * ReceiverHeaderLen = <source_nickname_len> + <content_aes_key_len> +
	 *    <content_aes_iv_len> + <content_len_len> + <signature_len>
	 *
	 * ReceiverHeaderContent = <source_nickname> + <content_aes_key> +
	 *    <content_aes_iv> + <content_len> + <signature>
	 *
	 * <signature> = RSA_private_encrypt(sender.priv, SHA256(<content>))
	 */
	unsigned char *receiver_header;
	size_t receiver_header_size;

	/* Content = AES-CBC(<content_aes_key>, <content_aes_iv>, DeflateCompress(<content>)) */
	unsigned char *content;
	size_t content_size;
} ue_cipher_message;

#endif
