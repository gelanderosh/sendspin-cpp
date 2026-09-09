// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#pragma once

#include "noise_state.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace sendspin {

struct ProtocolV1TransportMessage {
    uint8_t type{};
    std::vector<uint8_t> payload;
};

/// @brief Encodes and decodes authenticated protocol-v1 binary transport frames.
class ProtocolV1Transport {
public:
    static constexpr uint8_t JSON_TYPE = 0;
    static constexpr uint8_t FRAGMENT_MORE_TYPE = 2;
    static constexpr uint8_t FRAGMENT_END_TYPE = 3;
    static constexpr size_t MAX_APPLICATION_PAYLOAD_SIZE = 65518;

    bool encrypt(uint8_t type, const uint8_t* payload, size_t payload_size,
                 NoiseCipherState* cipher, std::vector<std::vector<uint8_t>>* frames) const;

    /// @brief Decrypts one frame and returns a completed application message when available.
    /// A valid non-final fragment returns true with an empty optional.
    bool decrypt(const uint8_t* frame, size_t frame_size, NoiseCipherState* cipher,
                 std::optional<ProtocolV1TransportMessage>* message);

    void reset();

private:
    bool fragment_in_flight_{};
    uint8_t fragment_type_{};
    std::vector<uint8_t> fragment_payload_;
};

}  // namespace sendspin