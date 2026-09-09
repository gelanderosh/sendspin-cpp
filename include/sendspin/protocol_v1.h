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

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

class SendspinPersistenceProvider;

struct SendspinProtocolV1ClientInit {
    std::string client_id;
    static constexpr uint8_t VERSION = 1;
    static constexpr const char* SUITE = "25519_ChaChaPoly_SHA256";
};

struct SendspinProtocolV1ServerInit {
    std::string server_id;
};

enum class SendspinProtocolV1PskKind : uint8_t {
    SENTINEL,
    PAIRED,
};

/// @brief Utilities for protocol v1 persistent identity and pairing material.
class SendspinProtocolV1 {
public:
    static constexpr size_t KEY_SIZE = 32;
    using Key = std::array<uint8_t, KEY_SIZE>;

    /// @brief Derives the X25519 public key and unpadded base64url client ID.
    static bool derive_client_id(const Key& private_key, std::string* client_id);

    /// @brief Returns the built-in sentinel PSK for the first v1 connection.
    static bool sentinel_psk(Key* psk);

    /// @brief Derives the base64url identifier for a pairing PSK.
    static bool derive_psk_id(const Key& psk, std::string* psk_id);

    /// @brief Encodes bytes as unpadded RFC 4648 base64url.
    static bool base64url_encode(const uint8_t* input, size_t input_size, std::string* output);

    /// @brief Decodes an unpadded RFC 4648 base64url string, rejecting invalid encodings.
    static bool base64url_decode(const std::string& input, std::vector<uint8_t>* output);

    /// @brief Serializes the cleartext client/init message whose bytes seed the Noise prologue.
    static bool format_client_init(const SendspinProtocolV1ClientInit& init, std::string* message);

    /// @brief Parses and validates a cleartext server/init message without re-encoding it.
    static bool parse_server_init(const std::string& message, SendspinProtocolV1ServerInit* init);

    /// @brief Selects the paired PSK when its ID matches, otherwise the Sentinel PSK.
    static bool select_psk(const std::string& psk_id, SendspinPersistenceProvider* persistence,
                           Key* psk, SendspinProtocolV1PskKind* kind);
};

}  // namespace sendspin