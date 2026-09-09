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

#ifdef ESP_PLATFORM
#include <mbedtls/sha256.h>
#else
#include <openssl/sha.h>
#endif

namespace sendspin {

bool ProtocolCrypto::sha256(const uint8_t* input, size_t input_size, Sha256Digest* digest) {
    if (input == nullptr || digest == nullptr) {
        return false;
    }

#ifdef ESP_PLATFORM
    return mbedtls_sha256(input, input_size, digest->data(), 0) == 0;
#else
    return SHA256(input, input_size, digest->data()) != nullptr;
#endif
}

}  // namespace sendspin