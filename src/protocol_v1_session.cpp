// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include "protocol_v1_session.h"

#include <ArduinoJson.h>

#include <array>

namespace sendspin {

namespace {

bool parse_noise_message(const std::string& message, std::vector<uint8_t>* data) {
    JsonDocument document;
    if (data == nullptr || deserializeJson(document, message) != DeserializationError::Ok ||
        !document["type"].is<const char*>() ||
        std::string(document["type"].as<const char*>()) != "noise/handshake" ||
        !document["payload"]["data"].is<const char*>()) {
        return false;
    }
    return SendspinProtocolV1::base64url_decode(document["payload"]["data"].as<const char*>(), data);
}

bool parse_psk_id(const std::vector<uint8_t>& payload, std::string* psk_id) {
    JsonDocument document;
    return psk_id != nullptr && deserializeJson(document, payload.data(), payload.size()) == DeserializationError::Ok &&
           document.is<JsonObject>() && document["psk_id"].is<const char*>() &&
           ((*psk_id = document["psk_id"].as<const char*>()), true);
}

bool format_noise_message(const std::vector<uint8_t>& data, std::string* message) {
    std::string encoded;
    if (message == nullptr || !SendspinProtocolV1::base64url_encode(data.data(), data.size(), &encoded)) {
        return false;
    }
    JsonDocument document;
    document["type"] = "noise/handshake";
    document["payload"]["data"] = encoded;
    message->clear();
    serializeJson(document, *message);
    return !message->empty();
}

}  // namespace

bool ProtocolV1ResponderSession::begin(const SendspinProtocolV1::Key& identity_private_key,
                                       const std::string& client_id,
                                       SendspinPersistenceProvider* persistence,
                                       std::string* client_init) {
    SendspinProtocolV1ClientInit init{.client_id = client_id};
    if (client_init == nullptr || !SendspinProtocolV1::format_client_init(init, client_init)) {
        phase_ = Phase::FAILED;
        return false;
    }
    identity_private_key_ = identity_private_key;
    persistence_ = persistence;
    client_init_ = *client_init;
    server_id_.clear();
    transport_.reset();
    phase_ = Phase::WAIT_SERVER_INIT;
    return true;
}

bool ProtocolV1ResponderSession::receive_server_init(const std::string& server_init) {
    SendspinProtocolV1ServerInit init;
    std::vector<uint8_t> server_key;
    ProtocolCrypto::X25519Key ephemeral_private_key{};
    if (phase_ != Phase::WAIT_SERVER_INIT || !SendspinProtocolV1::parse_server_init(server_init, &init) ||
        !SendspinProtocolV1::base64url_decode(init.server_id, &server_key) ||
        server_key.size() != ProtocolCrypto::X25519_KEY_SIZE ||
        !ProtocolCrypto::random_bytes(ephemeral_private_key.data(), ephemeral_private_key.size())) {
        phase_ = Phase::FAILED;
        return false;
    }
    ProtocolCrypto::X25519Key remote_static{};
    std::copy(server_key.begin(), server_key.end(), remote_static.begin());
    std::string prologue = client_init_ + server_init;
    if (!handshake_.initialize(false, identity_private_key_, remote_static, ephemeral_private_key,
                               reinterpret_cast<const uint8_t*>(prologue.data()), prologue.size())) {
        phase_ = Phase::FAILED;
        return false;
    }
    server_id_ = init.server_id;
    phase_ = Phase::WAIT_MESSAGE_ONE;
    return true;
}

bool ProtocolV1ResponderSession::receive_server_handshake(const std::string& message,
                                                          std::string* client_handshake) {
    std::vector<uint8_t> encoded_message;
    std::vector<uint8_t> payload;
    std::string psk_id;
    SendspinProtocolV1::Key psk{};
    std::vector<uint8_t> response;
    constexpr std::array<uint8_t, 2> empty_object{'{', '}'};
    if (phase_ != Phase::WAIT_MESSAGE_ONE || !parse_noise_message(message, &encoded_message) ||
        !handshake_.read_message(encoded_message.data(), encoded_message.size(), &payload) ||
        !parse_psk_id(payload, &psk_id) || !SendspinProtocolV1::select_psk(psk_id, persistence_, &psk, &psk_kind_) ||
        !handshake_.set_psk(psk) || !handshake_.write_message(empty_object.data(), empty_object.size(), &response) ||
        !format_noise_message(response, client_handshake) ||
        !handshake_.split(&receive_cipher_, &send_cipher_)) {
        phase_ = Phase::FAILED;
        return false;
    }
    phase_ = Phase::READY;
    return true;
}

bool ProtocolV1ResponderSession::ready() const { return phase_ == Phase::READY; }
const std::string& ProtocolV1ResponderSession::server_id() const { return server_id_; }
SendspinProtocolV1PskKind ProtocolV1ResponderSession::psk_kind() const { return psk_kind_; }
NoiseCipherState* ProtocolV1ResponderSession::send_cipher() { return ready() ? &send_cipher_ : nullptr; }
NoiseCipherState* ProtocolV1ResponderSession::receive_cipher() { return ready() ? &receive_cipher_ : nullptr; }
ProtocolV1Transport* ProtocolV1ResponderSession::transport() { return ready() ? &transport_ : nullptr; }

}  // namespace sendspin