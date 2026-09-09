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

#include "sendspin/protocol_v1.h"

#include <gtest/gtest.h>

namespace sendspin {

TEST(SendspinProtocolV1Test, DerivesUnpaddedBase64UrlClientId) {
    constexpr SendspinProtocolV1::Key private_key{
        0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D, 0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2,
        0x66, 0x45, 0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A, 0xB1, 0x77, 0xFB, 0xA5,
        0x1D, 0xB9, 0x2C, 0x2A,
    };
    std::string client_id;

    ASSERT_TRUE(SendspinProtocolV1::derive_client_id(private_key, &client_id));
    EXPECT_EQ(client_id, "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo");
    EXPECT_EQ(client_id.size(), 43U);
}

TEST(SendspinProtocolV1Test, DerivesStableSentinelPskIdentifier) {
    SendspinProtocolV1::Key psk{};
    std::string psk_id;

    ASSERT_TRUE(SendspinProtocolV1::sentinel_psk(&psk));
    ASSERT_TRUE(SendspinProtocolV1::derive_psk_id(psk, &psk_id));
    EXPECT_EQ(psk_id, "GFsV9tLaSQm9HcFWpKsgYQOr7wFTvNUtkmFwuVz3zoo");
    EXPECT_EQ(psk_id.size(), 43U);
}

}  // namespace sendspin