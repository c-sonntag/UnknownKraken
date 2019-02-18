/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <uk/crypto/api/encoding/base64_decode.h>
#include <uk/crypto/impl/encoding/base64_decode_impl.h>

unsigned char *uk_crypto_base64_decode(const unsigned char *src, size_t len, size_t *out_len) {
    size_t tmp_out_len;
    unsigned char *result;

    result = uk_crypto_base64_decode_impl(src, len, &tmp_out_len);

    *out_len = tmp_out_len;

    return result;
}
