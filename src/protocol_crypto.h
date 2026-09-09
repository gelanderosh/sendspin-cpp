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

#include <array>
#include <cstddef>
#include <cstdint>

namespace sendspin {

/// @brief Cross-platform primitives used by the Sendspin v1 Noise transport.
class ProtocolCrypto {
public:
    static constexpr size_t SHA256_SIZE = 32;
    using Sha256Digest = std::array<uint8_t, SHA256_SIZE>;

    /// @brief Calculates the SHA-256 digest of the supplied bytes.
    static bool sha256(const uint8_t* input, size_t input_size, Sha256Digest* digest);
};

}  // namespace sendspin