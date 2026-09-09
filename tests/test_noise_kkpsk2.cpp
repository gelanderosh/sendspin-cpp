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

#include <gtest/gtest.h>

#include <array>
#include <cstring>

namespace sendspin {

TEST(NoiseKkPsk2HandshakeTest, CompletesMutualAuthenticationAndTransportSetup) {
    constexpr ProtocolCrypto::X25519Key initiator_static_private{
        0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D, 0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2,
        0x66, 0x45, 0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A, 0xB1, 0x77, 0xFB, 0xA5,
        0x1D, 0xB9, 0x2C, 0x2A,
    };
    constexpr ProtocolCrypto::X25519Key responder_static_private{
        0x5D, 0xAB, 0x08, 0x7E, 0x62, 0x4A, 0x8A, 0x4B, 0x79, 0xE1, 0x7F, 0x8B, 0x83, 0x80,
        0x0E, 0xE6, 0x6F, 0x3B, 0xB1, 0x29, 0x26, 0x18, 0xB6, 0xFD, 0x1C, 0x2F, 0x8B, 0x27,
        0xFF, 0x88, 0xE0, 0xEB,
    };
    constexpr ProtocolCrypto::X25519Key initiator_ephemeral_private{
        0x90, 0x20, 0x7B, 0xAD, 0xB8, 0x31, 0xE7, 0x02, 0xE6, 0x4D, 0xA7, 0xF9, 0xC2, 0xAA,
        0xA9, 0x7A, 0x7C, 0x5E, 0xD9, 0x72, 0x58, 0xC9, 0x48, 0x9B, 0x1D, 0x64, 0xAF, 0xCF,
        0x3A, 0x7A, 0x4D, 0xC1,
    };
    constexpr ProtocolCrypto::X25519Key responder_ephemeral_private{
        0xE8, 0x61, 0xA0, 0xD2, 0x90, 0x51, 0xF1, 0xA5, 0xB8, 0xE4, 0x9E, 0x5D, 0xB1, 0xD4,
        0xAF, 0x2A, 0xA0, 0xB2, 0xA0, 0x52, 0x5F, 0xD2, 0x9A, 0xF9, 0x2D, 0xB8, 0xC0, 0xA4,
        0x70, 0x2E, 0xA4, 0x5B,
    };
    constexpr ProtocolCrypto::Sha256Digest psk{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F,
    };
    constexpr char prologue[] = "client/initserver/init";
    constexpr std::array<uint8_t, 4> first_payload{'i', 'n', 'i', 't'};
    constexpr std::array<uint8_t, 2> second_payload{'{', '}'};
    ProtocolCrypto::X25519Key initiator_static_public{};
    ProtocolCrypto::X25519Key responder_static_public{};
    NoiseKkPsk2Handshake initiator;
    NoiseKkPsk2Handshake responder;
    NoiseCipherState initiator_send;
    NoiseCipherState responder_receive;
    NoiseCipherState initiator_receive;
    NoiseCipherState responder_send;
    std::vector<uint8_t> message_one;
    std::vector<uint8_t> message_two;
    std::vector<uint8_t> received_payload;
    std::vector<uint8_t> transport_ciphertext;

    ASSERT_TRUE(ProtocolCrypto::x25519_public_key(initiator_static_private, &initiator_static_public));
    ASSERT_TRUE(ProtocolCrypto::x25519_public_key(responder_static_private, &responder_static_public));
    ASSERT_TRUE(initiator.initialize(true, initiator_static_private, responder_static_public,
                                    initiator_ephemeral_private,
                                    reinterpret_cast<const uint8_t*>(prologue), sizeof(prologue) - 1));
    ASSERT_TRUE(responder.initialize(false, responder_static_private, initiator_static_public,
                                    responder_ephemeral_private,
                                    reinterpret_cast<const uint8_t*>(prologue), sizeof(prologue) - 1));
    ASSERT_TRUE(initiator.set_psk(psk));
    ASSERT_TRUE(initiator.write_message(first_payload.data(), first_payload.size(), &message_one));
    EXPECT_EQ(message_one.size(), NoiseKkPsk2Handshake::kHandshakeMessageOneSize + first_payload.size());
    ASSERT_TRUE(responder.read_message(message_one.data(), message_one.size(), &received_payload));
    EXPECT_EQ(received_payload, std::vector<uint8_t>(first_payload.begin(), first_payload.end()));
    ASSERT_TRUE(responder.set_psk(psk));
    ASSERT_TRUE(responder.write_message(second_payload.data(), second_payload.size(), &message_two));
    EXPECT_EQ(message_two.size(), NoiseKkPsk2Handshake::kHandshakeMessageTwoSize + second_payload.size());
    ASSERT_TRUE(initiator.read_message(message_two.data(), message_two.size(), &received_payload));
    EXPECT_EQ(received_payload, std::vector<uint8_t>(second_payload.begin(), second_payload.end()));
    EXPECT_TRUE(initiator.is_complete());
    EXPECT_TRUE(responder.is_complete());
    EXPECT_EQ(initiator.handshake_hash(), responder.handshake_hash());

    ASSERT_TRUE(initiator.split(&initiator_send, &initiator_receive));
    ASSERT_TRUE(responder.split(&responder_receive, &responder_send));
    ASSERT_TRUE(initiator_send.encrypt_with_ad(nullptr, 0, first_payload.data(), first_payload.size(),
                                                &transport_ciphertext));
    ASSERT_TRUE(responder_receive.decrypt_with_ad(nullptr, 0, transport_ciphertext.data(),
                                                  transport_ciphertext.size(), &received_payload));
    EXPECT_EQ(received_payload, std::vector<uint8_t>(first_payload.begin(), first_payload.end()));
}

TEST(NoiseKkPsk2HandshakeTest, RejectsTamperedHandshakePayload) {
    ProtocolCrypto::X25519Key first_static_private{1};
    ProtocolCrypto::X25519Key second_static_private{2};
    ProtocolCrypto::X25519Key first_ephemeral_private{3};
    ProtocolCrypto::X25519Key second_ephemeral_private{4};
    ProtocolCrypto::X25519Key first_static_public{};
    ProtocolCrypto::X25519Key second_static_public{};
    ProtocolCrypto::Sha256Digest psk{};
    NoiseKkPsk2Handshake initiator;
    NoiseKkPsk2Handshake responder;
    std::vector<uint8_t> message;
    std::vector<uint8_t> payload;

    ASSERT_TRUE(ProtocolCrypto::x25519_public_key(first_static_private, &first_static_public));
    ASSERT_TRUE(ProtocolCrypto::x25519_public_key(second_static_private, &second_static_public));
    ASSERT_TRUE(initiator.initialize(true, first_static_private, second_static_public, first_ephemeral_private,
                                    nullptr, 0));
    ASSERT_TRUE(responder.initialize(false, second_static_private, first_static_public, second_ephemeral_private,
                                    nullptr, 0));
    ASSERT_TRUE(initiator.set_psk(psk));
    ASSERT_TRUE(initiator.write_message(nullptr, 0, &message));
    message.back() ^= 1U;
    EXPECT_FALSE(responder.read_message(message.data(), message.size(), &payload));
}

}  // namespace sendspin