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

#include "protocol_crypto.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

namespace sendspin {

TEST(ProtocolCryptoTest, Sha256MatchesKnownAnswer) {
    constexpr std::array<uint8_t, 3> input{'a', 'b', 'c'};
    constexpr ProtocolCrypto::Sha256Digest expected{
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40,
        0xDE, 0x5D, 0xAE, 0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17,
        0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
    };
    ProtocolCrypto::Sha256Digest digest{};

    ASSERT_TRUE(ProtocolCrypto::sha256(input.data(), input.size(), &digest));
    EXPECT_EQ(digest, expected);
}

TEST(ProtocolCryptoTest, Sha256RejectsNullArguments) {
    ProtocolCrypto::Sha256Digest digest{};
    EXPECT_FALSE(ProtocolCrypto::sha256(nullptr, 0, &digest));
    EXPECT_FALSE(ProtocolCrypto::sha256(digest.data(), digest.size(), nullptr));
}

TEST(ProtocolCryptoTest, HkdfSha256MatchesRfc5869CaseOne) {
    constexpr std::array<uint8_t, 22> input_key_material{
        0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
        0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
    };
    constexpr std::array<uint8_t, 13> salt{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    };
    constexpr std::array<uint8_t, 10> info{0xF0, 0xF1, 0xF2, 0xF3, 0xF4,
                                             0xF5, 0xF6, 0xF7, 0xF8, 0xF9};
    constexpr std::array<uint8_t, 42> expected{
        0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A, 0x90, 0x43, 0x4F, 0x64,
        0xD0, 0x36, 0x2F, 0x2A, 0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A, 0x5A, 0x4C,
        0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4, 0xC5, 0xBF, 0x34, 0x00, 0x72,
        0x08, 0xD5, 0xB8, 0x87, 0x18, 0x58, 0x65,
    };
    std::array<uint8_t, expected.size()> output{};
    constexpr ProtocolCrypto::Sha256Digest expected_prk{
        0x07, 0x77, 0x09, 0x36, 0x2C, 0x2E, 0x32, 0xDF, 0x0D, 0xDC, 0x3F,
        0x0D, 0xC4, 0x7B, 0xBA, 0x63, 0x90, 0xB6, 0xC7, 0x3B, 0xB5, 0x0F,
        0x9C, 0x31, 0x22, 0xEC, 0x84, 0x4A, 0xD7, 0xC2, 0xB3, 0xE5,
    };
    ProtocolCrypto::Sha256Digest prk{};

    ASSERT_TRUE(ProtocolCrypto::hmac_sha256(salt.data(), salt.size(), input_key_material.data(),
                                             input_key_material.size(), &prk));
    EXPECT_EQ(prk, expected_prk);
    ASSERT_TRUE(ProtocolCrypto::hkdf_sha256(salt.data(), salt.size(), input_key_material.data(),
                                             input_key_material.size(), info.data(), info.size(),
                                             output.data(), output.size()));
    EXPECT_EQ(output, expected);
}

}  // namespace sendspin