// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include "protocol_v1_transport.h"

#include <algorithm>

namespace sendspin {

namespace {

bool encrypt_frame(uint8_t type, const uint8_t* payload, size_t payload_size, NoiseCipherState* cipher,
                   std::vector<std::vector<uint8_t>>* frames) {
    std::vector<uint8_t> plaintext;
    plaintext.reserve(payload_size + 1);
    plaintext.push_back(type);
    if (payload_size > 0) {
        plaintext.insert(plaintext.end(), payload, payload + payload_size);
    }
    std::vector<uint8_t> ciphertext;
    if (!cipher->encrypt_with_ad(nullptr, 0, plaintext.data(), plaintext.size(), &ciphertext)) {
        return false;
    }
    frames->push_back(std::move(ciphertext));
    return true;
}

}  // namespace

bool ProtocolV1Transport::encrypt(uint8_t type, const uint8_t* payload, size_t payload_size,
                                  NoiseCipherState* cipher,
                                  std::vector<std::vector<uint8_t>>* frames) const {
    if (cipher == nullptr || frames == nullptr || (payload_size > 0 && payload == nullptr) ||
        type == FRAGMENT_MORE_TYPE || type == FRAGMENT_END_TYPE) {
        return false;
    }
    frames->clear();
    if (payload_size <= MAX_APPLICATION_PAYLOAD_SIZE) {
        return encrypt_frame(type, payload, payload_size, cipher, frames);
    }

    size_t offset = 0;
    const size_t first_data_size = MAX_APPLICATION_PAYLOAD_SIZE - 1;
    std::vector<uint8_t> first_payload;
    first_payload.reserve(first_data_size + 1);
    first_payload.push_back(type);
    const size_t first_chunk = std::min(first_data_size, payload_size);
    first_payload.insert(first_payload.end(), payload, payload + first_chunk);
    if (!encrypt_frame(FRAGMENT_MORE_TYPE, first_payload.data(), first_payload.size(), cipher, frames)) {
        return false;
    }
    offset = first_chunk;
    while (payload_size - offset > MAX_APPLICATION_PAYLOAD_SIZE) {
        if (!encrypt_frame(FRAGMENT_MORE_TYPE, payload + offset, MAX_APPLICATION_PAYLOAD_SIZE, cipher,
                           frames)) {
            return false;
        }
        offset += MAX_APPLICATION_PAYLOAD_SIZE;
    }
    return encrypt_frame(FRAGMENT_END_TYPE, payload + offset, payload_size - offset, cipher, frames);
}

bool ProtocolV1Transport::decrypt(const uint8_t* frame, size_t frame_size, NoiseCipherState* cipher,
                                  std::optional<ProtocolV1TransportMessage>* message) {
    if (cipher == nullptr || message == nullptr || frame == nullptr || frame_size == 0) {
        return false;
    }
    message->reset();
    std::vector<uint8_t> plaintext;
    if (!cipher->decrypt_with_ad(nullptr, 0, frame, frame_size, &plaintext) || plaintext.empty()) {
        return false;
    }
    const uint8_t type = plaintext.front();
    const uint8_t* payload = plaintext.data() + 1;
    const size_t payload_size = plaintext.size() - 1;
    if (type == FRAGMENT_MORE_TYPE) {
        if (!fragment_in_flight_) {
            if (payload_size == 0 || payload[0] == FRAGMENT_MORE_TYPE || payload[0] == FRAGMENT_END_TYPE) {
                return false;
            }
            fragment_in_flight_ = true;
            fragment_type_ = payload[0];
            fragment_payload_.assign(payload + 1, payload + payload_size);
            return true;
        }
        fragment_payload_.insert(fragment_payload_.end(), payload, payload + payload_size);
        return true;
    }
    if (type == FRAGMENT_END_TYPE) {
        if (!fragment_in_flight_) {
            return false;
        }
        fragment_payload_.insert(fragment_payload_.end(), payload, payload + payload_size);
        *message = ProtocolV1TransportMessage{fragment_type_, std::move(fragment_payload_)};
        reset();
        return true;
    }
    if (fragment_in_flight_) {
        return false;
    }
    *message = ProtocolV1TransportMessage{type, std::vector<uint8_t>(payload, payload + payload_size)};
    return true;
}

void ProtocolV1Transport::reset() {
    fragment_in_flight_ = false;
    fragment_type_ = 0;
    fragment_payload_.clear();
}

}  // namespace sendspin