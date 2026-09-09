// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include "noise_kkpsk2.h"
#include "protocol_v1_session.h"

#include <gtest/gtest.h>

namespace sendspin {

TEST(ProtocolV1ResponderSessionTest, CompletesInitialServerInitiatedHandshake) {
    ProtocolCrypto::X25519Key client_private{};
    ProtocolCrypto::X25519Key server_private{};
    ProtocolCrypto::X25519Key server_ephemeral{};
    client_private.fill(0x11);
    server_private.fill(0x22);
    server_ephemeral.fill(0x33);
    std::string client_id;
    std::string server_id;
    ASSERT_TRUE(SendspinProtocolV1::derive_client_id(client_private, &client_id));
    ASSERT_TRUE(SendspinProtocolV1::derive_client_id(server_private, &server_id));

    ProtocolV1ResponderSession responder;
    std::string client_init;
    ASSERT_TRUE(responder.begin(client_private, client_id, nullptr, &client_init));
    const std::string server_init = "{\"type\":\"server/init\",\"payload\":{\"server_id\":\"" +
                                    server_id + "\",\"version\":1}}";
    ASSERT_TRUE(responder.receive_server_init(server_init));

    ProtocolCrypto::X25519Key client_public{};
    ASSERT_TRUE(ProtocolCrypto::x25519_public_key(client_private, &client_public));
    NoiseKkPsk2Handshake initiator;
    const std::string prologue = client_init + server_init;
    ASSERT_TRUE(initiator.initialize(true, server_private, client_public, server_ephemeral,
                                    reinterpret_cast<const uint8_t*>(prologue.data()), prologue.size()));
    SendspinProtocolV1::Key sentinel{};
    std::string psk_id;
    ASSERT_TRUE(SendspinProtocolV1::sentinel_psk(&sentinel));
    ASSERT_TRUE(SendspinProtocolV1::derive_psk_id(sentinel, &psk_id));
    ASSERT_TRUE(initiator.set_psk(sentinel));
    const std::string payload = "{\"psk_id\":\"" + psk_id + "\"}";
    std::vector<uint8_t> message_one;
    ASSERT_TRUE(initiator.write_message(reinterpret_cast<const uint8_t*>(payload.data()), payload.size(),
                                        &message_one));
    std::string encoded_message_one;
    ASSERT_TRUE(SendspinProtocolV1::base64url_encode(message_one.data(), message_one.size(),
                                                      &encoded_message_one));
    const std::string server_handshake =
        "{\"type\":\"noise/handshake\",\"payload\":{\"data\":\"" + encoded_message_one + "\"}}";

    std::string client_handshake;
    ASSERT_TRUE(responder.receive_server_handshake(server_handshake, &client_handshake));
    EXPECT_TRUE(responder.ready());
    EXPECT_EQ(responder.server_id(), server_id);
    EXPECT_EQ(responder.psk_kind(), SendspinProtocolV1PskKind::SENTINEL);

    const auto start = client_handshake.find("\"data\":\"");
    ASSERT_NE(start, std::string::npos);
    const size_t data_start = start + 8;
    const size_t data_end = client_handshake.find('"', data_start);
    ASSERT_NE(data_end, std::string::npos);
    std::vector<uint8_t> message_two;
    ASSERT_TRUE(SendspinProtocolV1::base64url_decode(client_handshake.substr(data_start, data_end - data_start),
                                                      &message_two));
    std::vector<uint8_t> response_payload;
    ASSERT_TRUE(initiator.read_message(message_two.data(), message_two.size(), &response_payload));
    EXPECT_EQ(response_payload, std::vector<uint8_t>({'{', '}'}));

    NoiseCipherState server_send;
    NoiseCipherState server_receive;
    ASSERT_TRUE(initiator.split(&server_send, &server_receive));
    std::vector<std::vector<uint8_t>> frames;
    const std::vector<uint8_t> hello{'{', '}'};
    ASSERT_TRUE(responder.transport()->encrypt(0, hello.data(), hello.size(), &server_send, &frames));
    std::optional<ProtocolV1TransportMessage> received;
    ASSERT_TRUE(responder.transport()->decrypt(frames.front().data(), frames.front().size(),
                                               responder.receive_cipher(), &received));
    ASSERT_TRUE(received.has_value());
    EXPECT_EQ(received->payload, hello);
}

}  // namespace sendspin