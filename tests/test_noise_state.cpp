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

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <limits>

namespace sendspin {

TEST(NoiseCipherStateTest, EncryptsWithIndependentDirectionalNonces) {
    constexpr NoiseCipherState::Key key{
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
        0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
        0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    };
    constexpr std::array<uint8_t, 3> associated_data{0x01, 0x02, 0x03};
    constexpr std::array<uint8_t, 5> plaintext{'h', 'e', 'l', 'l', 'o'};
    NoiseCipherState sender;
    NoiseCipherState receiver;
    std::vector<uint8_t> first_ciphertext;
    std::vector<uint8_t> second_ciphertext;
    std::vector<uint8_t> decrypted;

    sender.initialize_key(key);
    receiver.initialize_key(key);
    ASSERT_TRUE(sender.encrypt_with_ad(associated_data.data(), associated_data.size(), plaintext.data(),
                                       plaintext.size(), &first_ciphertext));
    ASSERT_TRUE(sender.encrypt_with_ad(associated_data.data(), associated_data.size(), plaintext.data(),
                                       plaintext.size(), &second_ciphertext));
    EXPECT_NE(first_ciphertext, second_ciphertext);
    ASSERT_TRUE(receiver.decrypt_with_ad(associated_data.data(), associated_data.size(), first_ciphertext.data(),
                                         first_ciphertext.size(), &decrypted));
    ASSERT_EQ(decrypted.size(), plaintext.size());
    EXPECT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    ASSERT_TRUE(receiver.decrypt_with_ad(associated_data.data(), associated_data.size(), second_ciphertext.data(),
                                         second_ciphertext.size(), &decrypted));
    EXPECT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
}

TEST(NoiseCipherStateTest, RejectsReservedNonceWithoutEncrypting) {
    NoiseCipherState cipher;
    NoiseCipherState::Key key{};
    std::vector<uint8_t> ciphertext;
    cipher.initialize_key(key);

    EXPECT_FALSE(cipher.set_nonce(std::numeric_limits<uint64_t>::max()));
    EXPECT_TRUE(cipher.set_nonce(std::numeric_limits<uint64_t>::max() - 1));
    EXPECT_TRUE(cipher.encrypt_with_ad(nullptr, 0, nullptr, 0, &ciphertext));
    EXPECT_FALSE(cipher.encrypt_with_ad(nullptr, 0, nullptr, 0, &ciphertext));
}

TEST(NoiseSymmetricStateTest, MaintainsTranscriptAndDerivesMatchingTransportKeys) {
    constexpr char protocol_name[] = "Noise_KKpsk2_25519_ChaChaPoly_SHA256";
    constexpr char prologue[] = "test-prologue";
    constexpr std::array<uint8_t, 32> psk{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    constexpr NoiseSymmetricState::Hash expected_initial_hash{
        0x57, 0x95, 0xCC, 0xF5, 0xCA, 0x33, 0x51, 0xF0, 0x91, 0x04, 0x3E,
        0xF6, 0x82, 0x6D, 0x4A, 0xE1, 0x5C, 0x94, 0xAF, 0xD8, 0x97, 0x25,
        0x74, 0xC9, 0x41, 0x31, 0xE9, 0x4C, 0x79, 0xA7, 0x9C, 0xD0,
    };
    NoiseSymmetricState initiator;
    NoiseSymmetricState responder;
    NoiseCipherState initiator_send;
    NoiseCipherState responder_receive;
    NoiseCipherState initiator_receive;
    NoiseCipherState responder_send;
    constexpr std::array<uint8_t, 4> payload{'t', 'e', 's', 't'};
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> decrypted;

    ASSERT_TRUE(initiator.initialize(reinterpret_cast<const uint8_t*>(protocol_name),
                                     sizeof(protocol_name) - 1));
    EXPECT_EQ(initiator.handshake_hash(), expected_initial_hash);
    ASSERT_TRUE(initiator.mix_hash(reinterpret_cast<const uint8_t*>(prologue), sizeof(prologue) - 1));
    ASSERT_TRUE(initiator.mix_key_and_hash(psk.data(), psk.size()));

    ASSERT_TRUE(responder.initialize(reinterpret_cast<const uint8_t*>(protocol_name),
                                     sizeof(protocol_name) - 1));
    ASSERT_TRUE(responder.mix_hash(reinterpret_cast<const uint8_t*>(prologue), sizeof(prologue) - 1));
    ASSERT_TRUE(responder.mix_key_and_hash(psk.data(), psk.size()));
    EXPECT_EQ(initiator.handshake_hash(), responder.handshake_hash());
    ASSERT_TRUE(initiator.split(&initiator_send, &initiator_receive));
    ASSERT_TRUE(responder.split(&responder_receive, &responder_send));

    ASSERT_TRUE(initiator_send.encrypt_with_ad(nullptr, 0, payload.data(), payload.size(), &ciphertext));
    ASSERT_TRUE(responder_receive.decrypt_with_ad(nullptr, 0, ciphertext.data(), ciphertext.size(), &decrypted));
    EXPECT_EQ(decrypted, std::vector<uint8_t>(payload.begin(), payload.end()));
}

}  // namespace sendspin