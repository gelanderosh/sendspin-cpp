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

#include "sendspin/client.h"
#include "protocol_crypto.h"

#include <ArduinoJson.h>
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

bool is_base64url_key_id(const std::string& value) {
    return value.size() == 43 && std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
               (character >= '0' && character <= '9') || character == '-' || character == '_';
    });
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

bool SendspinProtocolV1::format_client_init(const SendspinProtocolV1ClientInit& init,
                                            std::string* message) {
    if (message == nullptr || !is_base64url_key_id(init.client_id)) {
        return false;
    }
    JsonDocument document;
    document["type"] = "client/init";
    document["payload"]["client_id"] = init.client_id;
    document["payload"]["version"] = SendspinProtocolV1ClientInit::VERSION;
    document["payload"]["suite"] = SendspinProtocolV1ClientInit::SUITE;
    message->clear();
    serializeJson(document, *message);
    return !message->empty();
}

bool SendspinProtocolV1::parse_server_init(const std::string& message,
                                            SendspinProtocolV1ServerInit* init) {
    if (init == nullptr || message.empty()) {
        return false;
    }
    JsonDocument document;
    if (deserializeJson(document, message) != DeserializationError::Ok ||
        !document["type"].is<const char*>() ||
        std::string(document["type"].as<const char*>()) != "server/init" ||
        !document["payload"]["server_id"].is<const char*>() ||
        !document["payload"]["version"].is<uint8_t>() ||
        document["payload"]["version"].as<uint8_t>() != SendspinProtocolV1ClientInit::VERSION) {
        return false;
    }
    const std::string server_id = document["payload"]["server_id"].as<const char*>();
    if (!is_base64url_key_id(server_id)) {
        return false;
    }
    init->server_id = server_id;
    return true;
}

bool SendspinProtocolV1::select_psk(const std::string& psk_id,
                                    SendspinPersistenceProvider* persistence, Key* psk,
                                    SendspinProtocolV1PskKind* kind) {
    if (psk == nullptr || kind == nullptr || !is_base64url_key_id(psk_id)) {
        return false;
    }
    if (persistence != nullptr) {
        const auto paired_psk = persistence->load_protocol_v1_psk();
        if (paired_psk.has_value()) {
            std::string paired_psk_id;
            if (!derive_psk_id(*paired_psk, &paired_psk_id)) {
                return false;
            }
            if (psk_id == paired_psk_id) {
                *psk = *paired_psk;
                *kind = SendspinProtocolV1PskKind::PAIRED;
                return true;
            }
        }
    }
    if (!sentinel_psk(psk)) {
        return false;
    }
    std::string sentinel_psk_id;
    if (!derive_psk_id(*psk, &sentinel_psk_id) || psk_id != sentinel_psk_id) {
        return false;
    }
    *kind = SendspinProtocolV1PskKind::SENTINEL;
    return true;
}

}  // namespace sendspin