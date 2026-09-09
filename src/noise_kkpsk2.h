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

#include "noise_state.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace sendspin {

/// @brief Deterministic Noise_KKpsk2_25519_ChaChaPoly_SHA256 handshake state.
class NoiseKkPsk2Handshake {
public:
    struct KeyPair {
        ProtocolCrypto::X25519Key private_key;
        ProtocolCrypto::X25519Key public_key;
    };

    static constexpr size_t kHandshakeMessageOneSize = ProtocolCrypto::X25519_KEY_SIZE +
                                                        ProtocolCrypto::CHACHA20_POLY1305_TAG_SIZE;
    static constexpr size_t kHandshakeMessageTwoSize = ProtocolCrypto::X25519_KEY_SIZE +
                                                        ProtocolCrypto::CHACHA20_POLY1305_TAG_SIZE;

    bool initialize(bool initiator, const ProtocolCrypto::X25519Key& local_static_private_key,
                    const ProtocolCrypto::X25519Key& remote_static_public_key,
                    const ProtocolCrypto::X25519Key& ephemeral_private_key,
                    const ProtocolCrypto::Sha256Digest& psk, const uint8_t* prologue,
                    size_t prologue_size);

    bool write_message(const uint8_t* payload, size_t payload_size, std::vector<uint8_t>* message);
    bool read_message(const uint8_t* message, size_t message_size, std::vector<uint8_t>* payload);
    bool is_complete() const;
    const ProtocolCrypto::Sha256Digest& handshake_hash() const;
    bool split(NoiseCipherState* initiator_to_responder,
               NoiseCipherState* responder_to_initiator) const;

private:
    enum class Stage : uint8_t {
        kUninitialized,
        kInitiatorWriteMessageOne,
        kInitiatorReadMessageTwo,
        kResponderReadMessageOne,
        kResponderWriteMessageTwo,
        kComplete,
        kFailed,
    };

    bool mix_dh(const ProtocolCrypto::X25519Key& private_key,
                const ProtocolCrypto::X25519Key& public_key);
    bool mix_ephemeral_public_key(const ProtocolCrypto::X25519Key& public_key);

    bool initiator_{};
    Stage stage_{Stage::kUninitialized};
    KeyPair local_static_{};
    KeyPair local_ephemeral_{};
    ProtocolCrypto::X25519Key remote_static_{};
    ProtocolCrypto::X25519Key remote_ephemeral_{};
    ProtocolCrypto::Sha256Digest psk_{};
    NoiseSymmetricState symmetric_state_{};
};

}  // namespace sendspin