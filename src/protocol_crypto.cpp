// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "protocol_crypto.h"

#include <algorithm>
#include <array>
#include <cstring>

#ifdef ESP_PLATFORM
#include <mbedtls/sha256.h>
#else
#include <openssl/sha.h>
#endif

namespace sendspin {

bool ProtocolCrypto::sha256(const uint8_t* input, size_t input_size, Sha256Digest* digest) {
    if (input == nullptr || digest == nullptr) {
        return false;
    }

#ifdef ESP_PLATFORM
    return mbedtls_sha256(input, input_size, digest->data(), 0) == 0;
#else
    return SHA256(input, input_size, digest->data()) != nullptr;
#endif
}

bool ProtocolCrypto::hmac_sha256(const uint8_t* key, size_t key_size, const uint8_t* input,
                                 size_t input_size, Sha256Digest* digest) {
    if (key == nullptr || input == nullptr || digest == nullptr) {
        return false;
    }

    constexpr size_t block_size = 64;
    std::array<uint8_t, block_size> padded_key{};
    if (key_size > block_size) {
        Sha256Digest key_digest{};
        if (!sha256(key, key_size, &key_digest)) {
            return false;
        }
        std::copy(key_digest.begin(), key_digest.end(), padded_key.begin());
    } else {
        std::copy(key, key + key_size, padded_key.begin());
    }

    std::array<uint8_t, block_size> inner_key{};
    std::array<uint8_t, block_size> outer_key{};
    for (size_t index = 0; index < block_size; ++index) {
        inner_key[index] = padded_key[index] ^ 0x36U;
        outer_key[index] = padded_key[index] ^ 0x5CU;
    }

    std::vector<uint8_t> inner_message;
    inner_message.reserve(block_size + input_size);
    inner_message.insert(inner_message.end(), inner_key.begin(), inner_key.end());
    inner_message.insert(inner_message.end(), input, input + input_size);
    Sha256Digest inner_digest{};
    if (!sha256(inner_message.data(), inner_message.size(), &inner_digest)) {
        return false;
    }

    std::array<uint8_t, block_size + SHA256_SIZE> outer_message{};
    std::copy(outer_key.begin(), outer_key.end(), outer_message.begin());
    std::copy(inner_digest.begin(), inner_digest.end(), outer_message.begin() + block_size);
    return sha256(outer_message.data(), outer_message.size(), digest);
}

bool ProtocolCrypto::hkdf_sha256(const uint8_t* salt, size_t salt_size, const uint8_t* input,
                                 size_t input_size, const uint8_t* info, size_t info_size,
                                 uint8_t* output, size_t output_size) {
    if (input == nullptr || output == nullptr || (salt_size > 0 && salt == nullptr) ||
        (info_size > 0 && info == nullptr) || output_size > 255 * SHA256_SIZE) {
        return false;
    }

    std::array<uint8_t, SHA256_SIZE> zero_salt{};
    Sha256Digest prk{};
    const uint8_t* extract_salt = salt_size == 0 ? zero_salt.data() : salt;
    const size_t extract_salt_size = salt_size == 0 ? zero_salt.size() : salt_size;
    if (!hmac_sha256(extract_salt, extract_salt_size, input, input_size, &prk)) {
        return false;
    }

    Sha256Digest previous{};
    size_t previous_size = 0;
    size_t offset = 0;
    uint8_t counter = 1;
    while (offset < output_size) {
        std::vector<uint8_t> expand_input;
        expand_input.reserve(previous_size + info_size + 1);
        expand_input.insert(expand_input.end(), previous.begin(), previous.begin() + previous_size);
        if (info_size > 0) {
            expand_input.insert(expand_input.end(), info, info + info_size);
        }
        expand_input.push_back(counter++);
        if (!hmac_sha256(prk.data(), prk.size(), expand_input.data(), expand_input.size(), &previous)) {
            return false;
        }
        const size_t written = std::min(SHA256_SIZE, output_size - offset);
        std::copy(previous.begin(), previous.begin() + written, output + offset);
        offset += written;
        previous_size = SHA256_SIZE;
    }
    return true;
}

}  // namespace sendspin