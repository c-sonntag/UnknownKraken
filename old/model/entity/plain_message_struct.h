#ifndef UNKNOWNECHO_PLAIN_MESSAGE_STRUCT_H
#define UNKNOWNECHO_PLAIN_MESSAGE_STRUCT_H

#include <stddef.h>

typedef struct {
	unsigned char *packet_type;
	size_t packet_type_len;

	unsigned char *destination_nickname;
	size_t destination_nickname_len;

	unsigned char *source_nickname;
	size_t source_nickname_len;

	unsigned char *signature;
	size_t signature_len;

	unsigned char *key;
	size_t key_len;

	unsigned char *iv;
	size_t iv_len;

	unsigned char *content;
	size_t content_len;

	unsigned char *content_len_uchar;
	size_t content_len_uchar_size;
} ue_plain_message;

#endif
