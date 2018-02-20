#include <unknownecho/protocol/message.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/byte/byte_utility.h>

ue_message *ue_message_create() {
    ue_message *message;

    ue_safe_alloc(message, ue_message, 1);
    message->source_nickname = NULL;
    message->content = NULL;
    message->content_size = 0;

    return message;
}

void ue_message_destroy(ue_message *message) {
    if (message) {
        ue_safe_free(message->source_nickname);
        ue_safe_free(message->content);
        ue_safe_free(message);
    }
}

void ue_message_clean_up(ue_message *message) {
    if (message) {
        ue_safe_free(message->source_nickname);
        ue_safe_free(message->content);
        message->content_size = 0;
    }
}

bool ue_message_set_source_nickname(ue_message *message, char *source_nickname) {
    message->source_nickname = ue_string_create_from(source_nickname);
    return true;
}

bool ue_message_set_content_char(ue_message *message, char *content) {
    message->content = ue_bytes_create_from_string(content);
    return true;
}

bool ue_message_set_content_uchar(ue_message *message, unsigned char *content, size_t content_size) {
    message->content = ue_bytes_create_from_bytes(content, content_size);
    return true;
}
