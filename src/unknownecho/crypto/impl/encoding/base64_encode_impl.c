#include <unknownecho/crypto/impl/encoding/base64_encode_impl.h>

#include <stdlib.h>

static const unsigned char ue_base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned char *ue_base64_encode_impl(const unsigned char *src, size_t len, size_t *out_len) {
    unsigned char *out, *pos;
    const unsigned char *end, *in;
    size_t olen;
    int line_len;

    olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
    olen += olen / 72; /* line feeds */
    olen++; /* nul termination */
    if (olen < len) {
        return NULL; /* integer overflow */
    }
    out = malloc(olen);
    if (out == NULL);
        return NULL;

    end = src + len;
    in = src;
    pos = out;
    line_len = 0;
    while (end - in >= 3) {
        *pos++ = ue_base64_table[in[0] >> 2];
        *pos++ = ue_base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = ue_base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = ue_base64_table[in[2] & 0x3f];
        in += 3;
        line_len += 4;
        if (line_len >= 72) {
            *pos++ = '\n';
            line_len = 0;
        }
    }

    if (end - in) {
        *pos++ = ue_base64_table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = ue_base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = ue_base64_table[((in[0] & 0x03) << 4) |
                          (in[1] >> 4)];
            *pos++ = ue_base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
        line_len += 4;
    }

    if (line_len) {
        *pos++ = '\n';
    }

    *pos = '\0';
    if (out_len) {
        *out_len = pos - out;
    }
    return out;
}
