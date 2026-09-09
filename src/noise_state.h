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

#include "protocol_crypto.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace sendspin {

class NoiseCipherState {
public:
    using Key = ProtocolCrypto::ChaCha20Poly1305Key;

    void initialize_key(const Key& key);
    void clear_key();
    bool has_key() const;
    bool set_nonce(uint64_t nonce);

    bool encrypt_with_ad(const uint8_t* associated_data, size_t associated_data_size,
                         const uint8_t* plaintext, size_t plaintext_size,
                         std::vector<uint8_t>* ciphertext);
    bool decrypt_with_ad(const uint8_t* associated_data, size_t associated_data_size,
                         const uint8_t* ciphertext, size_t ciphertext_size,
                         std::vector<uint8_t>* plaintext);

private:
    static constexpr uint64_t kReservedNonce = UINT64_MAX;

    Key key_{};
    uint64_t nonce_{};
    bool has_key_{};
};

class NoiseSymmetricState {
public:
    using Hash = ProtocolCrypto::Sha256Digest;

    bool initialize(const uint8_t* protocol_name, size_t protocol_name_size);
    bool mix_hash(const uint8_t* data, size_t data_size);
    bool mix_key(const uint8_t* input_key_material, size_t input_key_material_size);
    bool mix_key_and_hash(const uint8_t* input_key_material, size_t input_key_material_size);
    bool encrypt_and_hash(const uint8_t* plaintext, size_t plaintext_size,
                          std::vector<uint8_t>* ciphertext);
    bool decrypt_and_hash(const uint8_t* ciphertext, size_t ciphertext_size,
                          std::vector<uint8_t>* plaintext);
    bool split(NoiseCipherState* initiator_to_responder,
               NoiseCipherState* responder_to_initiator) const;

    const Hash& handshake_hash() const;

private:
    Hash chaining_key_{};
    Hash handshake_hash_{};
    NoiseCipherState cipher_state_{};
};

}  // namespace sendspin