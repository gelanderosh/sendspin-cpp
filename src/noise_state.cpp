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

#include "noise_state.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace sendspin {

namespace {

bool copy_bytes(const uint8_t* input, size_t input_size, std::vector<uint8_t>* output) {
    if (output == nullptr || (input_size > 0 && input == nullptr)) {
        return false;
    }
    output->clear();
    if (input_size > 0) {
        output->assign(input, input + input_size);
    }
    return true;
}

ProtocolCrypto::ChaCha20Poly1305Nonce make_noise_nonce(uint64_t nonce) {
    ProtocolCrypto::ChaCha20Poly1305Nonce output{};
    for (size_t index = 0; index < sizeof(nonce); ++index) {
        output[4 + index] = static_cast<uint8_t>(nonce >> (index * 8));
    }
    return output;
}

}  // namespace

void NoiseCipherState::initialize_key(const Key& key) {
    key_ = key;
    nonce_ = 0;
    has_key_ = true;
}

void NoiseCipherState::clear_key() {
    key_.fill(0);
    nonce_ = 0;
    has_key_ = false;
}

bool NoiseCipherState::has_key() const {
    return has_key_;
}

bool NoiseCipherState::set_nonce(uint64_t nonce) {
    if (nonce == kReservedNonce) {
        return false;
    }
    nonce_ = nonce;
    return true;
}

bool NoiseCipherState::encrypt_with_ad(const uint8_t* associated_data, size_t associated_data_size,
                                        const uint8_t* plaintext, size_t plaintext_size,
                                        std::vector<uint8_t>* ciphertext) {
    if (ciphertext == nullptr || (associated_data_size > 0 && associated_data == nullptr) ||
        (plaintext_size > 0 && plaintext == nullptr)) {
        return false;
    }
    if (!has_key_) {
        return copy_bytes(plaintext, plaintext_size, ciphertext);
    }
    if (nonce_ == kReservedNonce) {
        return false;
    }

    ciphertext->resize(plaintext_size + ProtocolCrypto::CHACHA20_POLY1305_TAG_SIZE);
    ProtocolCrypto::ChaCha20Poly1305Tag tag{};
    if (!ProtocolCrypto::chacha20_poly1305_encrypt(key_, make_noise_nonce(nonce_), associated_data,
                                                    associated_data_size, plaintext, plaintext_size,
                                                    ciphertext->data(), &tag)) {
        ciphertext->clear();
        return false;
    }
    std::copy(tag.begin(), tag.end(), ciphertext->begin() + plaintext_size);
    ++nonce_;
    return true;
}

bool NoiseCipherState::decrypt_with_ad(const uint8_t* associated_data, size_t associated_data_size,
                                        const uint8_t* ciphertext, size_t ciphertext_size,
                                        std::vector<uint8_t>* plaintext) {
    if (plaintext == nullptr || (associated_data_size > 0 && associated_data == nullptr) ||
        (ciphertext_size > 0 && ciphertext == nullptr)) {
        return false;
    }
    if (!has_key_) {
        return copy_bytes(ciphertext, ciphertext_size, plaintext);
    }
    if (nonce_ == kReservedNonce || ciphertext_size < ProtocolCrypto::CHACHA20_POLY1305_TAG_SIZE) {
        return false;
    }

    const size_t encrypted_size = ciphertext_size - ProtocolCrypto::CHACHA20_POLY1305_TAG_SIZE;
    ProtocolCrypto::ChaCha20Poly1305Tag tag{};
    std::copy(ciphertext + encrypted_size, ciphertext + ciphertext_size, tag.begin());
    plaintext->resize(encrypted_size);
    if (!ProtocolCrypto::chacha20_poly1305_decrypt(key_, make_noise_nonce(nonce_), associated_data,
                                                    associated_data_size, ciphertext, encrypted_size, tag,
                                                    plaintext->data())) {
        plaintext->clear();
        return false;
    }
    ++nonce_;
    return true;
}

bool NoiseSymmetricState::initialize(const uint8_t* protocol_name, size_t protocol_name_size) {
    if (protocol_name == nullptr || protocol_name_size == 0) {
        return false;
    }
    if (protocol_name_size <= handshake_hash_.size()) {
        handshake_hash_.fill(0);
        std::copy(protocol_name, protocol_name + protocol_name_size, handshake_hash_.begin());
    } else if (!ProtocolCrypto::sha256(protocol_name, protocol_name_size, &handshake_hash_)) {
        return false;
    }
    chaining_key_ = handshake_hash_;
    cipher_state_.clear_key();
    return true;
}

bool NoiseSymmetricState::mix_hash(const uint8_t* data, size_t data_size) {
    if (data_size > 0 && data == nullptr) {
        return false;
    }
    std::vector<uint8_t> input;
    input.reserve(handshake_hash_.size() + data_size);
    input.insert(input.end(), handshake_hash_.begin(), handshake_hash_.end());
    if (data_size > 0) {
        input.insert(input.end(), data, data + data_size);
    }
    return ProtocolCrypto::sha256(input.data(), input.size(), &handshake_hash_);
}

bool NoiseSymmetricState::mix_key(const uint8_t* input_key_material, size_t input_key_material_size) {
    if (input_key_material == nullptr || input_key_material_size == 0) {
        return false;
    }
    std::array<uint8_t, ProtocolCrypto::SHA256_SIZE * 2> output{};
    if (!ProtocolCrypto::hkdf_sha256(chaining_key_.data(), chaining_key_.size(), input_key_material,
                                     input_key_material_size, nullptr, 0, output.data(), output.size())) {
        return false;
    }
    std::copy_n(output.begin(), chaining_key_.size(), chaining_key_.begin());
    NoiseCipherState::Key key{};
    std::copy_n(output.begin() + chaining_key_.size(), key.size(), key.begin());
    cipher_state_.initialize_key(key);
    return true;
}

bool NoiseSymmetricState::mix_key_and_hash(const uint8_t* input_key_material,
                                            size_t input_key_material_size) {
    if (input_key_material == nullptr || input_key_material_size == 0) {
        return false;
    }
    std::array<uint8_t, ProtocolCrypto::SHA256_SIZE * 3> output{};
    if (!ProtocolCrypto::hkdf_sha256(chaining_key_.data(), chaining_key_.size(), input_key_material,
                                     input_key_material_size, nullptr, 0, output.data(), output.size())) {
        return false;
    }
    std::copy_n(output.begin(), chaining_key_.size(), chaining_key_.begin());
    if (!mix_hash(output.data() + chaining_key_.size(), handshake_hash_.size())) {
        return false;
    }
    NoiseCipherState::Key key{};
    std::copy_n(output.begin() + chaining_key_.size() + handshake_hash_.size(), key.size(), key.begin());
    cipher_state_.initialize_key(key);
    return true;
}

bool NoiseSymmetricState::encrypt_and_hash(const uint8_t* plaintext, size_t plaintext_size,
                                            std::vector<uint8_t>* ciphertext) {
    return cipher_state_.encrypt_with_ad(handshake_hash_.data(), handshake_hash_.size(), plaintext,
                                         plaintext_size, ciphertext) &&
           mix_hash(ciphertext->data(), ciphertext->size());
}

bool NoiseSymmetricState::decrypt_and_hash(const uint8_t* ciphertext, size_t ciphertext_size,
                                            std::vector<uint8_t>* plaintext) {
    if (!cipher_state_.decrypt_with_ad(handshake_hash_.data(), handshake_hash_.size(), ciphertext,
                                       ciphertext_size, plaintext)) {
        return false;
    }
    return mix_hash(ciphertext, ciphertext_size);
}

bool NoiseSymmetricState::split(NoiseCipherState* initiator_to_responder,
                                 NoiseCipherState* responder_to_initiator) const {
    if (initiator_to_responder == nullptr || responder_to_initiator == nullptr) {
        return false;
    }
    std::array<uint8_t, ProtocolCrypto::SHA256_SIZE * 2> output{};
    if (!ProtocolCrypto::hkdf_sha256(chaining_key_.data(), chaining_key_.size(), nullptr, 0, nullptr, 0,
                                     output.data(), output.size())) {
        return false;
    }
    NoiseCipherState::Key initiator_key{};
    NoiseCipherState::Key responder_key{};
    std::copy_n(output.begin(), initiator_key.size(), initiator_key.begin());
    std::copy_n(output.begin() + initiator_key.size(), responder_key.size(), responder_key.begin());
    initiator_to_responder->initialize_key(initiator_key);
    responder_to_initiator->initialize_key(responder_key);
    return true;
}

const NoiseSymmetricState::Hash& NoiseSymmetricState::handshake_hash() const {
    return handshake_hash_;
}

}  // namespace sendspin