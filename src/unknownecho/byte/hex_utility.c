#include <unknownecho/byte/hex_utility.h>
#include <unknownecho/system/alloc.h>

#include <string.h>

char *ue_bytes_to_hex(unsigned char *bytes, size_t bytes_count) {
    char *hex;
    size_t i;

    ue_safe_alloc(hex, char, bytes_count * 2 + 3);

    strcat(hex, "0x");
    for(i = 0; i < bytes_count; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }

    return hex;
}
