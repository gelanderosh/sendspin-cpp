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

#include "noise_kkpsk2.h"

#include <algorithm>
#include <array>

namespace sendspin {

namespace {

constexpr char kProtocolName[] = "Noise_KKpsk2_25519_ChaChaPoly_SHA256";

}  // namespace

bool NoiseKkPsk2Handshake::initialize(bool initiator,
                                      const ProtocolCrypto::X25519Key& local_static_private_key,
                                      const ProtocolCrypto::X25519Key& remote_static_public_key,
                                      const ProtocolCrypto::X25519Key& ephemeral_private_key,
                                      const uint8_t* prologue, size_t prologue_size) {
    if ((prologue_size > 0 && prologue == nullptr) ||
        !ProtocolCrypto::x25519_public_key(local_static_private_key, &local_static_.public_key) ||
        !ProtocolCrypto::x25519_public_key(ephemeral_private_key, &local_ephemeral_.public_key) ||
        !symmetric_state_.initialize(reinterpret_cast<const uint8_t*>(kProtocolName),
                                     sizeof(kProtocolName) - 1) ||
        !symmetric_state_.mix_hash(prologue, prologue_size)) {
        stage_ = Stage::kFailed;
        return false;
    }

    initiator_ = initiator;
    local_static_.private_key = local_static_private_key;
    local_ephemeral_.private_key = ephemeral_private_key;
    remote_static_ = remote_static_public_key;
    psk_.fill(0);
    psk_set_ = false;
    if (!symmetric_state_.mix_hash(initiator_ ? local_static_.public_key.data() : remote_static_.data(),
                                   ProtocolCrypto::X25519_KEY_SIZE) ||
        !symmetric_state_.mix_hash(initiator_ ? remote_static_.data() : local_static_.public_key.data(),
                                   ProtocolCrypto::X25519_KEY_SIZE)) {
        stage_ = Stage::kFailed;
        return false;
    }
    stage_ = initiator_ ? Stage::kInitiatorWriteMessageOne : Stage::kResponderReadMessageOne;
    return true;
}

bool NoiseKkPsk2Handshake::set_psk(const ProtocolCrypto::Sha256Digest& psk) {
    if (stage_ != Stage::kInitiatorWriteMessageOne && stage_ != Stage::kResponderWriteMessageTwo) {
        return false;
    }
    psk_ = psk;
    psk_set_ = true;
    return true;
}

bool NoiseKkPsk2Handshake::mix_dh(const ProtocolCrypto::X25519Key& private_key,
                                   const ProtocolCrypto::X25519Key& public_key) {
    ProtocolCrypto::X25519Key shared_secret{};
    return ProtocolCrypto::x25519_shared_secret(private_key, public_key, &shared_secret) &&
           symmetric_state_.mix_key(shared_secret.data(), shared_secret.size());
}

bool NoiseKkPsk2Handshake::mix_ephemeral_public_key(const ProtocolCrypto::X25519Key& public_key) {
    return symmetric_state_.mix_hash(public_key.data(), public_key.size()) &&
           symmetric_state_.mix_key(public_key.data(), public_key.size());
}

bool NoiseKkPsk2Handshake::write_message(const uint8_t* payload, size_t payload_size,
                                          std::vector<uint8_t>* message) {
    if (message == nullptr || (payload_size > 0 && payload == nullptr)) {
        return false;
    }
    message->clear();
    if (stage_ == Stage::kInitiatorWriteMessageOne) {
        if (!psk_set_ || !mix_ephemeral_public_key(local_ephemeral_.public_key) ||
            !mix_dh(local_ephemeral_.private_key, remote_static_) ||
            !mix_dh(local_static_.private_key, remote_static_) ||
            !symmetric_state_.encrypt_and_hash(payload, payload_size, message)) {
            stage_ = Stage::kFailed;
            return false;
        }
        message->insert(message->begin(), local_ephemeral_.public_key.begin(), local_ephemeral_.public_key.end());
        stage_ = Stage::kInitiatorReadMessageTwo;
        return true;
    }
    if (stage_ == Stage::kResponderWriteMessageTwo) {
        if (!psk_set_ || !mix_ephemeral_public_key(local_ephemeral_.public_key) ||
            !mix_dh(local_ephemeral_.private_key, remote_ephemeral_) ||
            !mix_dh(local_ephemeral_.private_key, remote_static_) ||
            !symmetric_state_.mix_key_and_hash(psk_.data(), psk_.size()) ||
            !symmetric_state_.encrypt_and_hash(payload, payload_size, message)) {
            stage_ = Stage::kFailed;
            return false;
        }
        message->insert(message->begin(), local_ephemeral_.public_key.begin(), local_ephemeral_.public_key.end());
        stage_ = Stage::kComplete;
        return true;
    }
    return false;
}

bool NoiseKkPsk2Handshake::read_message(const uint8_t* message, size_t message_size,
                                         std::vector<uint8_t>* payload) {
    if (payload == nullptr || message == nullptr) {
        return false;
    }
    if (stage_ == Stage::kResponderReadMessageOne) {
        if (message_size < kHandshakeMessageOneSize) {
            stage_ = Stage::kFailed;
            return false;
        }
        std::copy_n(message, remote_ephemeral_.size(), remote_ephemeral_.begin());
        if (!mix_ephemeral_public_key(remote_ephemeral_) ||
            !mix_dh(local_static_.private_key, remote_ephemeral_) ||
            !mix_dh(local_static_.private_key, remote_static_) ||
            !symmetric_state_.decrypt_and_hash(message + remote_ephemeral_.size(),
                                                message_size - remote_ephemeral_.size(), payload)) {
            stage_ = Stage::kFailed;
            return false;
        }
        stage_ = Stage::kResponderWriteMessageTwo;
        return true;
    }
    if (stage_ == Stage::kInitiatorReadMessageTwo) {
        if (message_size < kHandshakeMessageTwoSize) {
            stage_ = Stage::kFailed;
            return false;
        }
        std::copy_n(message, remote_ephemeral_.size(), remote_ephemeral_.begin());
        if (!mix_ephemeral_public_key(remote_ephemeral_) ||
            !mix_dh(local_ephemeral_.private_key, remote_ephemeral_) ||
            !mix_dh(local_static_.private_key, remote_ephemeral_) ||
            !symmetric_state_.mix_key_and_hash(psk_.data(), psk_.size()) ||
            !symmetric_state_.decrypt_and_hash(message + remote_ephemeral_.size(),
                                                message_size - remote_ephemeral_.size(), payload)) {
            stage_ = Stage::kFailed;
            return false;
        }
        stage_ = Stage::kComplete;
        return true;
    }
    return false;
}

bool NoiseKkPsk2Handshake::is_complete() const {
    return stage_ == Stage::kComplete;
}

const ProtocolCrypto::Sha256Digest& NoiseKkPsk2Handshake::handshake_hash() const {
    return symmetric_state_.handshake_hash();
}

bool NoiseKkPsk2Handshake::split(NoiseCipherState* initiator_to_responder,
                                  NoiseCipherState* responder_to_initiator) const {
    return is_complete() && symmetric_state_.split(initiator_to_responder, responder_to_initiator);
}

}  // namespace sendspin