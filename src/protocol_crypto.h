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
#include <cstddef>
#include <cstdint>
#include <vector>

namespace sendspin {

/// @brief Cross-platform primitives used by the Sendspin v1 Noise transport.
class ProtocolCrypto {
public:
    static constexpr size_t SHA256_SIZE = 32;
    static constexpr size_t X25519_KEY_SIZE = 32;
    using Sha256Digest = std::array<uint8_t, SHA256_SIZE>;
    using X25519Key = std::array<uint8_t, X25519_KEY_SIZE>;

    /// @brief Calculates the SHA-256 digest of the supplied bytes.
    static bool sha256(const uint8_t* input, size_t input_size, Sha256Digest* digest);

    /// @brief Calculates HMAC-SHA256 for the supplied key and message.
    static bool hmac_sha256(const uint8_t* key, size_t key_size, const uint8_t* input,
                            size_t input_size, Sha256Digest* digest);

    /// @brief Expands key material using HKDF-SHA256.
    static bool hkdf_sha256(const uint8_t* salt, size_t salt_size, const uint8_t* input,
                            size_t input_size, const uint8_t* info, size_t info_size,
                            uint8_t* output, size_t output_size);

    /// @brief Derives an X25519 public key from a private key in RFC 7748 byte order.
    static bool x25519_public_key(const X25519Key& private_key, X25519Key* public_key);

    /// @brief Derives an X25519 shared secret from a local private and peer public key.
    static bool x25519_shared_secret(const X25519Key& private_key,
                                     const X25519Key& peer_public_key,
                                     X25519Key* shared_secret);
};

}  // namespace sendspin