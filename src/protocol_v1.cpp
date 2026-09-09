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

#include "sendspin/protocol_v1.h"

#include "protocol_crypto.h"

#include <algorithm>

namespace sendspin {

namespace {

constexpr char kBase64UrlAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
constexpr char kSentinelPskLabel[] = "sendspin-sentinel-psk-v1";
constexpr char kPskIdLabel[] = "sendspin-psk-id-v1";

std::string base64url_encode(const uint8_t* input, size_t input_size) {
    std::string output;
    output.reserve((input_size * 4 + 2) / 3);
    size_t index = 0;
    while (index + 3 <= input_size) {
        const uint32_t value = (static_cast<uint32_t>(input[index]) << 16) |
                               (static_cast<uint32_t>(input[index + 1]) << 8) |
                               input[index + 2];
        output.push_back(kBase64UrlAlphabet[(value >> 18) & 0x3FU]);
        output.push_back(kBase64UrlAlphabet[(value >> 12) & 0x3FU]);
        output.push_back(kBase64UrlAlphabet[(value >> 6) & 0x3FU]);
        output.push_back(kBase64UrlAlphabet[value & 0x3FU]);
        index += 3;
    }
    if (index < input_size) {
        uint32_t value = static_cast<uint32_t>(input[index]) << 16;
        output.push_back(kBase64UrlAlphabet[(value >> 18) & 0x3FU]);
        if (index + 1 < input_size) {
            value |= static_cast<uint32_t>(input[index + 1]) << 8;
            output.push_back(kBase64UrlAlphabet[(value >> 12) & 0x3FU]);
            output.push_back(kBase64UrlAlphabet[(value >> 6) & 0x3FU]);
        } else {
            output.push_back(kBase64UrlAlphabet[(value >> 12) & 0x3FU]);
        }
    }
    return output;
}

}  // namespace

bool SendspinProtocolV1::derive_client_id(const Key& private_key, std::string* client_id) {
    if (client_id == nullptr) {
        return false;
    }
    ProtocolCrypto::X25519Key public_key{};
    if (!ProtocolCrypto::x25519_public_key(private_key, &public_key)) {
        return false;
    }
    *client_id = base64url_encode(public_key.data(), public_key.size());
    return true;
}

bool SendspinProtocolV1::sentinel_psk(Key* psk) {
    if (psk == nullptr) {
        return false;
    }
    return ProtocolCrypto::sha256(reinterpret_cast<const uint8_t*>(kSentinelPskLabel),
                                  sizeof(kSentinelPskLabel) - 1, psk);
}

bool SendspinProtocolV1::derive_psk_id(const Key& psk, std::string* psk_id) {
    if (psk_id == nullptr) {
        return false;
    }
    std::array<uint8_t, sizeof(kPskIdLabel) - 1 + KEY_SIZE> input{};
    std::copy_n(reinterpret_cast<const uint8_t*>(kPskIdLabel), sizeof(kPskIdLabel) - 1, input.begin());
    std::copy(psk.begin(), psk.end(), input.begin() + sizeof(kPskIdLabel) - 1);
    Key hash{};
    if (!ProtocolCrypto::sha256(input.data(), input.size(), &hash)) {
        return false;
    }
    *psk_id = base64url_encode(hash.data(), hash.size());
    return true;
}

}  // namespace sendspin