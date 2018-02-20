#ifndef UNKNOWNECHO_MESSAGE_H
#define UNKNOWNECHO_MESSAGE_H

#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct {
    char *source_nickname;
    /* other fields ? */
    unsigned char *content;
    size_t content_size;
} ue_message;

ue_message *ue_message_create();

void ue_message_destroy(ue_message *message);

void ue_message_clean_up(ue_message *message);

bool ue_message_set_source_nickname(ue_message *message, char *source_nickname);

bool ue_message_set_content_char(ue_message *message, char *content);

bool ue_message_set_content_uchar(ue_message *message, unsigned char *content, size_t content_size);

#endif
