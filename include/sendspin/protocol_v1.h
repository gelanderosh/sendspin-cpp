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
#include <string>

namespace sendspin {

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
};

}  // namespace sendspin