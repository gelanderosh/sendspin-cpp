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

#include "connection.h"

#include "platform/compiler.h"
#include "platform/logging.h"
#include "time_filter.h"

#include <algorithm>
#include <memory>

namespace sendspin {

static const char* const TAG = "sendspin.connection";

// ============================================================================
// Constructor / Destructor
// ============================================================================

SendspinConnection::~SendspinConnection() = default;

// ============================================================================
// Time filter
// ============================================================================

void SendspinConnection::init_time_filter() {
    this->time_filter_ = std::make_unique<SendspinTimeFilter>(SendspinTimeFilter::Config{});
}

// ============================================================================
// Message sending
// ============================================================================

SsErr SendspinConnection::send_goodbye_reason(SendspinGoodbyeReason reason,
                                              SendCompleteCallback on_complete) {
    // Goodbye is a control message that may legitimately be sent before the client/hello (e.g.,
    // when rejecting an excess connection), so it bypasses the pre-hello send gate.
    const std::string message = format_client_goodbye_message(reason);
    if (this->protocol_v1_session_ && this->protocol_v1_session_->ready()) {
        return this->send_protocol_json(message, std::move(on_complete));
    }
    return this->send_text_message(message, std::move(on_complete), true);
}

bool SendspinConnection::begin_protocol_v1(const SendspinProtocolV1::Key& identity_private_key,
                                           const std::string& client_id,
                                           SendspinPersistenceProvider* persistence,
                                           std::string* client_init) {
    protocol_v1_session_ = std::make_unique<ProtocolV1ResponderSession>();
    protocol_v1_activated_ = false;
    {
        std::lock_guard<std::mutex> lock(protocol_v1_activation_mutex_);
        protocol_v1_active_roles_.clear();
    }
    return protocol_v1_session_->begin(identity_private_key, client_id, persistence, client_init);
}

void SendspinConnection::apply_protocol_v1_activation(
    const std::optional<std::vector<std::string>>& active_roles) {
    std::lock_guard<std::mutex> lock(protocol_v1_activation_mutex_);
    if (active_roles.has_value()) {
        protocol_v1_active_roles_ = *active_roles;
    } else if (!protocol_v1_activated_.load(std::memory_order_acquire)) {
        protocol_v1_active_roles_.clear();
    }
    protocol_v1_activated_.store(true, std::memory_order_release);
}

bool SendspinConnection::is_protocol_v1_role_active(std::string_view role) const {
    if (!is_protocol_v1()) {
        return true;
    }
    std::lock_guard<std::mutex> lock(protocol_v1_activation_mutex_);
    return std::find(protocol_v1_active_roles_.begin(), protocol_v1_active_roles_.end(), role) !=
           protocol_v1_active_roles_.end();
}

SsErr SendspinConnection::send_protocol_json(const std::string& message, SendCompleteCallback cb) {
    if (!protocol_v1_session_ || !protocol_v1_session_->ready()) {
        return SsErr::INVALID_STATE;
    }
    std::vector<std::vector<uint8_t>> frames;
    if (!protocol_v1_session_->transport()->encrypt(
            ProtocolV1Transport::JSON_TYPE, reinterpret_cast<const uint8_t*>(message.data()), message.size(),
            protocol_v1_session_->send_cipher(), &frames)) {
        return SsErr::FAIL;
    }
    for (size_t index = 0; index < frames.size(); ++index) {
        const SsErr result = send_binary_message(frames[index].data(), frames[index].size(),
                                                 index + 1 == frames.size() ? cb : nullptr);
        if (result != SsErr::OK) {
            return result;
        }
    }
    return SsErr::OK;
}

// ============================================================================
// WebSocket payload buffer management
// ============================================================================

void SendspinConnection::deallocate_websocket_payload() {
    this->websocket_payload_.reset();
    this->websocket_write_offset_ = 0;
}

void SendspinConnection::reset_websocket_payload() {
    this->websocket_write_offset_ = 0;
}

uint8_t* SendspinConnection::prepare_receive_buffer(size_t data_len) {
    if (!this->websocket_payload_) {
        // First fragment - allocate new buffer
        if (!this->websocket_payload_.allocate(data_len, this->websocket_payload_location_)) {
            SS_LOGE(TAG, "Failed to allocate %zu bytes for websocket payload", data_len);
            return nullptr;
        }
        this->websocket_write_offset_ = 0;
    } else if (this->websocket_write_offset_ + data_len > this->websocket_payload_.size()) {
        // Need to expand buffer for additional fragment
        size_t new_len = this->websocket_write_offset_ + data_len;
        if (!this->websocket_payload_.realloc(new_len)) {
            SS_LOGE(TAG, "Failed to expand websocket payload to %zu bytes", new_len);
            this->deallocate_websocket_payload();
            return nullptr;
        }
    }

    return this->websocket_payload_.data() + this->websocket_write_offset_;
}

void SendspinConnection::commit_receive_buffer(size_t data_len) {
    this->websocket_write_offset_ += data_len;
}

SS_HOT void SendspinConnection::dispatch_completed_message(bool is_text, int64_t receive_time) {
    if (!this->websocket_payload_) {
        return;
    }

    if (!this->message_dispatch_enabled_.load(std::memory_order_acquire)) {
        this->reset_websocket_payload();
        return;
    }

    if (protocol_v1_session_) {
        const bool accepted = is_text
                                  ? dispatch_protocol_v1_text(std::string(
                                        reinterpret_cast<const char*>(websocket_payload_.data()),
                                        websocket_write_offset_))
                                  : dispatch_protocol_v1_binary(receive_time);
        if (!accepted) {
            this->disable_message_dispatch();
            this->reset_websocket_payload();
            this->abort_transport();
            return;
        }
    } else if (is_text) {
        // Hand the JSON callback a pointer straight into the reassembly buffer instead of copying
        // it into a std::string. The callback parses synchronously; reset_websocket_payload()
        // below makes the buffer reusable as soon as it returns, so the callback must not retain
        // the pointer. Not null-terminated; the length is authoritative.
        if (this->on_json_message_cb) {
            this->on_json_message_cb(this,
                                     reinterpret_cast<const char*>(this->websocket_payload_.data()),
                                     this->websocket_write_offset_, receive_time);
        }
    } else {
        // Binary message - connection retains buffer ownership, callback reads in-place
        if (this->on_binary_message_cb) {
            this->on_binary_message_cb(this, this->websocket_payload_.data(),
                                       this->websocket_write_offset_);
        }
    }

    // Reset write offset for next message; keep buffer allocated for reuse
    this->reset_websocket_payload();
}

bool SendspinConnection::dispatch_protocol_v1_text(const std::string& message) {
    if (!protocol_v1_session_ || protocol_v1_session_->ready()) {
        return false;
    }
    if (protocol_v1_session_->expects_server_init()) {
        if (!protocol_v1_session_->receive_server_init(message)) {
            return false;
        }
        server_information_.server_id = protocol_v1_session_->server_id();
        return true;
    }
    std::string response;
    if (!protocol_v1_session_->receive_server_handshake(message, &response)) {
        return false;
    }
    return send_text_message(response, nullptr, true) == SsErr::OK;
}

bool SendspinConnection::dispatch_protocol_v1_binary(int64_t receive_time) {
    if (!protocol_v1_session_ || !protocol_v1_session_->ready()) {
        return false;
    }
    std::optional<ProtocolV1TransportMessage> message;
    if (!protocol_v1_session_->transport()->decrypt(websocket_payload_.data(), websocket_write_offset_,
                                                    protocol_v1_session_->receive_cipher(), &message)) {
        return false;
    }
    if (!message.has_value()) {
        return true;
    }
    if (message->type == ProtocolV1Transport::JSON_TYPE && on_json_message_cb) {
        on_json_message_cb(this, reinterpret_cast<const char*>(message->payload.data()), message->payload.size(),
                           receive_time);
        return true;
    }
    if (message->type != ProtocolV1Transport::JSON_TYPE && on_binary_message_cb) {
        on_binary_message_cb(this, message->payload.data(), message->payload.size());
        return true;
    }
    return false;
}

}  // namespace sendspin
