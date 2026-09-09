// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include "protocol_v1_transport.h"

#include <gtest/gtest.h>

namespace sendspin {

TEST(ProtocolV1TransportTest, AuthenticatesAndRoundTripsSingleFrame) {
    NoiseCipherState sender;
    NoiseCipherState receiver;
    NoiseCipherState::Key key{};
    key.fill(0x5A);
    sender.initialize_key(key);
    receiver.initialize_key(key);
    ProtocolV1Transport transport;
    std::vector<std::vector<uint8_t>> frames;
    const std::vector<uint8_t> payload{'{', '}'};

    ASSERT_TRUE(transport.encrypt(ProtocolV1Transport::JSON_TYPE, payload.data(), payload.size(), &sender,
                                  &frames));
    ASSERT_EQ(frames.size(), 1U);
    std::optional<ProtocolV1TransportMessage> message;
    ASSERT_TRUE(transport.decrypt(frames[0].data(), frames[0].size(), &receiver, &message));
    ASSERT_TRUE(message.has_value());
    EXPECT_EQ(message->type, ProtocolV1Transport::JSON_TYPE);
    EXPECT_EQ(message->payload, payload);
}

TEST(ProtocolV1TransportTest, ReassemblesFragmentedPayload) {
    NoiseCipherState sender;
    NoiseCipherState receiver;
    NoiseCipherState::Key key{};
    key.fill(0x3C);
    sender.initialize_key(key);
    receiver.initialize_key(key);
    ProtocolV1Transport sender_transport;
    ProtocolV1Transport receiver_transport;
    std::vector<uint8_t> payload(ProtocolV1Transport::MAX_APPLICATION_PAYLOAD_SIZE + 7, 0xA5);
    std::vector<std::vector<uint8_t>> frames;

    ASSERT_TRUE(sender_transport.encrypt(4, payload.data(), payload.size(), &sender, &frames));
    ASSERT_EQ(frames.size(), 2U);
    std::optional<ProtocolV1TransportMessage> message;
    ASSERT_TRUE(receiver_transport.decrypt(frames[0].data(), frames[0].size(), &receiver, &message));
    EXPECT_FALSE(message.has_value());
    ASSERT_TRUE(receiver_transport.decrypt(frames[1].data(), frames[1].size(), &receiver, &message));
    ASSERT_TRUE(message.has_value());
    EXPECT_EQ(message->type, 4);
    EXPECT_EQ(message->payload, payload);
}

TEST(ProtocolV1TransportTest, RejectsTamperingAndMalformedFragments) {
    NoiseCipherState sender;
    NoiseCipherState receiver;
    NoiseCipherState::Key key{};
    key.fill(0x9A);
    sender.initialize_key(key);
    receiver.initialize_key(key);
    ProtocolV1Transport transport;
    std::vector<std::vector<uint8_t>> frames;
    const std::vector<uint8_t> payload{'x'};
    ASSERT_TRUE(transport.encrypt(4, payload.data(), payload.size(), &sender, &frames));
    frames[0][0] ^= 1;
    std::optional<ProtocolV1TransportMessage> message;
    EXPECT_FALSE(transport.decrypt(frames[0].data(), frames[0].size(), &receiver, &message));
}

}  // namespace sendspin