// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#pragma once

#include "noise_kkpsk2.h"
#include "protocol_v1_transport.h"
#include "sendspin/protocol_v1.h"

#include <string>

namespace sendspin {

/// @brief Client-responder state for the initial protocol-v1 Noise exchange.
class ProtocolV1ResponderSession {
public:
    bool begin(const SendspinProtocolV1::Key& identity_private_key, const std::string& client_id,
               SendspinPersistenceProvider* persistence, std::string* client_init);
    bool receive_server_init(const std::string& server_init);
    bool receive_server_handshake(const std::string& handshake, std::string* client_handshake);
    bool expects_server_init() const;
    bool ready() const;
    const std::string& server_id() const;
    SendspinProtocolV1PskKind psk_kind() const;
    NoiseCipherState* send_cipher();
    NoiseCipherState* receive_cipher();
    ProtocolV1Transport* transport();

private:
    enum class Phase : uint8_t { IDLE, WAIT_SERVER_INIT, WAIT_MESSAGE_ONE, READY, FAILED };

    Phase phase_{Phase::IDLE};
    SendspinProtocolV1::Key identity_private_key_{};
    SendspinPersistenceProvider* persistence_{};
    std::string client_init_;
    std::string server_id_;
    NoiseKkPsk2Handshake handshake_;
    NoiseCipherState send_cipher_;
    NoiseCipherState receive_cipher_;
    ProtocolV1Transport transport_;
    SendspinProtocolV1PskKind psk_kind_{SendspinProtocolV1PskKind::SENTINEL};
};

}  // namespace sendspin