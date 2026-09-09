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

}  // namespace sendspin