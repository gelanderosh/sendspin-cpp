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

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

#ifdef ESP_PLATFORM
#include <mbedtls/chachapoly.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#else
#include <openssl/evp.h>
#endif

namespace sendspin {

namespace {

ProtocolCrypto::X25519Key clamp_x25519_private_key(ProtocolCrypto::X25519Key private_key) {
    private_key[0] &= 248U;
    private_key[31] &= 127U;
    private_key[31] |= 64U;
    return private_key;
}

#ifdef ESP_PLATFORM
bool x25519_mbedtls(const ProtocolCrypto::X25519Key& private_key,
                    const ProtocolCrypto::X25519Key& peer_public_key,
                    ProtocolCrypto::X25519Key* shared_secret) {
    mbedtls_ecp_group group;
    mbedtls_ecp_point peer_point;
    mbedtls_mpi private_scalar;
    mbedtls_mpi shared_scalar;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&peer_point);
    mbedtls_mpi_init(&private_scalar);
    mbedtls_mpi_init(&shared_scalar);

    const auto clamped_key = clamp_x25519_private_key(private_key);
    const bool success = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
                         mbedtls_mpi_read_binary_le(&private_scalar, clamped_key.data(),
                                                    clamped_key.size()) == 0 &&
                         mbedtls_mpi_read_binary_le(&peer_point.MBEDTLS_PRIVATE(X),
                                                    peer_public_key.data(), peer_public_key.size()) == 0 &&
                         mbedtls_mpi_lset(&peer_point.MBEDTLS_PRIVATE(Z), 1) == 0 &&
                         mbedtls_ecdh_compute_shared(&group, &shared_scalar, &peer_point,
                                                     &private_scalar, nullptr, nullptr) == 0 &&
                         mbedtls_mpi_write_binary_le(&shared_scalar, shared_secret->data(),
                                                     shared_secret->size()) == 0;

    mbedtls_mpi_free(&shared_scalar);
    mbedtls_mpi_free(&private_scalar);
    mbedtls_ecp_point_free(&peer_point);
    mbedtls_ecp_group_free(&group);
    return success;
}
#else
bool x25519_openssl(const ProtocolCrypto::X25519Key& private_key,
                    const ProtocolCrypto::X25519Key& peer_public_key,
                    ProtocolCrypto::X25519Key* shared_secret) {
    EVP_PKEY* local = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                    private_key.data(), private_key.size());
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                  peer_public_key.data(), peer_public_key.size());
    EVP_PKEY_CTX* context = local != nullptr ? EVP_PKEY_CTX_new(local, nullptr) : nullptr;
    size_t output_size = shared_secret->size();
    const bool success = context != nullptr && peer != nullptr && EVP_PKEY_derive_init(context) == 1 &&
                         EVP_PKEY_derive_set_peer(context, peer) == 1 &&
                         EVP_PKEY_derive(context, shared_secret->data(), &output_size) == 1 &&
                         output_size == shared_secret->size();
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(local);
    return success;
}
#endif

bool is_valid_aead_input(const uint8_t* aad, size_t aad_size, const uint8_t* input,
                         size_t input_size, const uint8_t* output) {
    return (aad_size == 0 || aad != nullptr) && (input_size == 0 || input != nullptr) &&
           (input_size == 0 || output != nullptr);
}

#ifdef ESP_PLATFORM
bool chacha20_poly1305_encrypt_mbedtls(const ProtocolCrypto::ChaCha20Poly1305Key& key,
                                       const ProtocolCrypto::ChaCha20Poly1305Nonce& nonce,
                                       const uint8_t* aad, size_t aad_size, const uint8_t* plaintext,
                                       size_t plaintext_size, uint8_t* ciphertext,
                                       ProtocolCrypto::ChaCha20Poly1305Tag* tag) {
    mbedtls_chachapoly_context context;
    mbedtls_chachapoly_init(&context);
    const bool success = mbedtls_chachapoly_setkey(&context, key.data()) == 0 &&
                         mbedtls_chachapoly_encrypt_and_tag(&context, plaintext_size, nonce.data(),
                                                            aad, aad_size, plaintext, ciphertext,
                                                            tag->data()) == 0;
    mbedtls_chachapoly_free(&context);
    return success;
}

bool chacha20_poly1305_decrypt_mbedtls(const ProtocolCrypto::ChaCha20Poly1305Key& key,
                                       const ProtocolCrypto::ChaCha20Poly1305Nonce& nonce,
                                       const uint8_t* aad, size_t aad_size, const uint8_t* ciphertext,
                                       size_t ciphertext_size,
                                       const ProtocolCrypto::ChaCha20Poly1305Tag& tag,
                                       uint8_t* plaintext) {
    mbedtls_chachapoly_context context;
    mbedtls_chachapoly_init(&context);
    const bool success = mbedtls_chachapoly_setkey(&context, key.data()) == 0 &&
                         mbedtls_chachapoly_auth_decrypt(&context, ciphertext_size, nonce.data(),
                                                         aad, aad_size, tag.data(), ciphertext,
                                                         plaintext) == 0;
    mbedtls_chachapoly_free(&context);
    return success;
}
#else
bool chacha20_poly1305_encrypt_openssl(const ProtocolCrypto::ChaCha20Poly1305Key& key,
                                       const ProtocolCrypto::ChaCha20Poly1305Nonce& nonce,
                                       const uint8_t* aad, size_t aad_size, const uint8_t* plaintext,
                                       size_t plaintext_size, uint8_t* ciphertext,
                                       ProtocolCrypto::ChaCha20Poly1305Tag* tag) {
    if (aad_size > static_cast<size_t>(std::numeric_limits<int>::max()) ||
        plaintext_size > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    int output_size = 0;
    const bool success = context != nullptr &&
                         EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
                         EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
                         (aad_size == 0 || EVP_EncryptUpdate(context, nullptr, &output_size, aad,
                                                              static_cast<int>(aad_size)) == 1) &&
                         (plaintext_size == 0 || EVP_EncryptUpdate(context, ciphertext, &output_size, plaintext,
                                                                    static_cast<int>(plaintext_size)) == 1) &&
                         EVP_EncryptFinal_ex(context, ciphertext + output_size, &output_size) == 1 &&
                         EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, tag->size(), tag->data()) == 1;
    EVP_CIPHER_CTX_free(context);
    return success;
}

bool chacha20_poly1305_decrypt_openssl(const ProtocolCrypto::ChaCha20Poly1305Key& key,
                                       const ProtocolCrypto::ChaCha20Poly1305Nonce& nonce,
                                       const uint8_t* aad, size_t aad_size, const uint8_t* ciphertext,
                                       size_t ciphertext_size,
                                       const ProtocolCrypto::ChaCha20Poly1305Tag& tag,
                                       uint8_t* plaintext) {
    if (aad_size > static_cast<size_t>(std::numeric_limits<int>::max()) ||
        ciphertext_size > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    int output_size = 0;
    const bool success = context != nullptr &&
                         EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
                         EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
                         (aad_size == 0 || EVP_DecryptUpdate(context, nullptr, &output_size, aad,
                                                              static_cast<int>(aad_size)) == 1) &&
                         (ciphertext_size == 0 || EVP_DecryptUpdate(context, plaintext, &output_size, ciphertext,
                                                                     static_cast<int>(ciphertext_size)) == 1) &&
                         EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, tag.size(),
                                             const_cast<uint8_t*>(tag.data())) == 1 &&
                         EVP_DecryptFinal_ex(context, plaintext + output_size, &output_size) == 1;
    EVP_CIPHER_CTX_free(context);
    return success;
}
#endif

}  // namespace

bool ProtocolCrypto::sha256(const uint8_t* input, size_t input_size, Sha256Digest* digest) {
    if (input == nullptr || digest == nullptr) {
        return false;
    }

#ifdef ESP_PLATFORM
    return mbedtls_sha256(input, input_size, digest->data(), 0) == 0;
#else
    return EVP_Q_digest(nullptr, "SHA256", nullptr, input, input_size, digest->data(), nullptr) == 1;
#endif
}

bool ProtocolCrypto::hmac_sha256(const uint8_t* key, size_t key_size, const uint8_t* input,
                                 size_t input_size, Sha256Digest* digest) {
    if (key == nullptr || input == nullptr || digest == nullptr) {
        return false;
    }

    constexpr size_t block_size = 64;
    std::array<uint8_t, block_size> padded_key{};
    if (key_size > block_size) {
        Sha256Digest key_digest{};
        if (!sha256(key, key_size, &key_digest)) {
            return false;
        }
        std::copy(key_digest.begin(), key_digest.end(), padded_key.begin());
    } else {
        std::copy(key, key + key_size, padded_key.begin());
    }

    std::array<uint8_t, block_size> inner_key{};
    std::array<uint8_t, block_size> outer_key{};
    for (size_t index = 0; index < block_size; ++index) {
        inner_key[index] = padded_key[index] ^ 0x36U;
        outer_key[index] = padded_key[index] ^ 0x5CU;
    }

    std::vector<uint8_t> inner_message;
    inner_message.reserve(block_size + input_size);
    inner_message.insert(inner_message.end(), inner_key.begin(), inner_key.end());
    inner_message.insert(inner_message.end(), input, input + input_size);
    Sha256Digest inner_digest{};
    if (!sha256(inner_message.data(), inner_message.size(), &inner_digest)) {
        return false;
    }

    std::array<uint8_t, block_size + SHA256_SIZE> outer_message{};
    std::copy(outer_key.begin(), outer_key.end(), outer_message.begin());
    std::copy(inner_digest.begin(), inner_digest.end(), outer_message.begin() + block_size);
    return sha256(outer_message.data(), outer_message.size(), digest);
}

bool ProtocolCrypto::hkdf_sha256(const uint8_t* salt, size_t salt_size, const uint8_t* input,
                                 size_t input_size, const uint8_t* info, size_t info_size,
                                 uint8_t* output, size_t output_size) {
    if (input == nullptr || output == nullptr || (salt_size > 0 && salt == nullptr) ||
        (info_size > 0 && info == nullptr) || output_size > 255 * SHA256_SIZE) {
        return false;
    }

    std::array<uint8_t, SHA256_SIZE> zero_salt{};
    Sha256Digest prk{};
    const uint8_t* extract_salt = salt_size == 0 ? zero_salt.data() : salt;
    const size_t extract_salt_size = salt_size == 0 ? zero_salt.size() : salt_size;
    if (!hmac_sha256(extract_salt, extract_salt_size, input, input_size, &prk)) {
        return false;
    }

    Sha256Digest previous{};
    size_t previous_size = 0;
    size_t offset = 0;
    uint8_t counter = 1;
    while (offset < output_size) {
        std::vector<uint8_t> expand_input;
        expand_input.reserve(previous_size + info_size + 1);
        expand_input.insert(expand_input.end(), previous.begin(), previous.begin() + previous_size);
        if (info_size > 0) {
            expand_input.insert(expand_input.end(), info, info + info_size);
        }
        expand_input.push_back(counter++);
        if (!hmac_sha256(prk.data(), prk.size(), expand_input.data(), expand_input.size(), &previous)) {
            return false;
        }
        const size_t written = std::min(SHA256_SIZE, output_size - offset);
        std::copy(previous.begin(), previous.begin() + written, output + offset);
        offset += written;
        previous_size = SHA256_SIZE;
    }
    return true;
}

bool ProtocolCrypto::x25519_public_key(const X25519Key& private_key, X25519Key* public_key) {
    if (public_key == nullptr) {
        return false;
    }
    constexpr X25519Key basepoint{9};
    return x25519_shared_secret(private_key, basepoint, public_key);
}

bool ProtocolCrypto::x25519_shared_secret(const X25519Key& private_key,
                                          const X25519Key& peer_public_key,
                                          X25519Key* shared_secret) {
    if (shared_secret == nullptr) {
        return false;
    }
#ifdef ESP_PLATFORM
    return x25519_mbedtls(private_key, peer_public_key, shared_secret);
#else
    return x25519_openssl(clamp_x25519_private_key(private_key), peer_public_key, shared_secret);
#endif
}

bool ProtocolCrypto::chacha20_poly1305_encrypt(const ChaCha20Poly1305Key& key,
                                                const ChaCha20Poly1305Nonce& nonce,
                                                const uint8_t* aad, size_t aad_size,
                                                const uint8_t* plaintext, size_t plaintext_size,
                                                uint8_t* ciphertext, ChaCha20Poly1305Tag* tag) {
    if (tag == nullptr || !is_valid_aead_input(aad, aad_size, plaintext, plaintext_size, ciphertext)) {
        return false;
    }
#ifdef ESP_PLATFORM
    return chacha20_poly1305_encrypt_mbedtls(key, nonce, aad, aad_size, plaintext, plaintext_size,
                                             ciphertext, tag);
#else
    return chacha20_poly1305_encrypt_openssl(key, nonce, aad, aad_size, plaintext, plaintext_size,
                                             ciphertext, tag);
#endif
}

bool ProtocolCrypto::chacha20_poly1305_decrypt(const ChaCha20Poly1305Key& key,
                                                const ChaCha20Poly1305Nonce& nonce,
                                                const uint8_t* aad, size_t aad_size,
                                                const uint8_t* ciphertext, size_t ciphertext_size,
                                                const ChaCha20Poly1305Tag& tag, uint8_t* plaintext) {
    if (!is_valid_aead_input(aad, aad_size, ciphertext, ciphertext_size, plaintext)) {
        return false;
    }
#ifdef ESP_PLATFORM
    const bool success = chacha20_poly1305_decrypt_mbedtls(key, nonce, aad, aad_size, ciphertext,
                                                           ciphertext_size, tag, plaintext);
#else
    const bool success = chacha20_poly1305_decrypt_openssl(key, nonce, aad, aad_size, ciphertext,
                                                           ciphertext_size, tag, plaintext);
#endif
    if (!success && ciphertext_size > 0) {
        std::fill(plaintext, plaintext + ciphertext_size, 0);
    }
    return success;
}

}  // namespace sendspin