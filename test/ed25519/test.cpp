/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "../utils.hpp"

extern "C" {
#include <schnorrkel/schnorrkel.h>
}

TEST(Ed25519, GenerateKeypair) {
    std::array<uint8_t, ED25519_KEYPAIR_LENGTH> keypair;
    std::array<uint8_t, ED25519_SEED_LENGTH> seed = {42, 1, 2, 3, 4, 5};
    auto status = ed25519_keypair_from_seed(keypair.data(), seed.data());
    ASSERT_EQ(status, ED25519_RESULT_OK);
}

TEST(Ed25519, SignVerify) {
    std::array<uint8_t, ED25519_KEYPAIR_LENGTH> keypair {};
    std::array<uint8_t, ED25519_SEED_LENGTH> seed = {42, 1, 2, 3, 4, 5};
    auto status = ed25519_keypair_from_seed(keypair.data(), seed.data());
    ASSERT_EQ(status, ED25519_RESULT_OK);

    std::array<uint8_t, ED25519_SIGNATURE_LENGTH> signature {};
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!', '\n'};
    status = ed25519_sign(signature.data(), keypair.data(), message.data(), message.size());
    ASSERT_EQ(status, ED25519_RESULT_OK);

    std::array<uint8_t, ED25519_PUBLIC_KEY_LENGTH> public_key {};
    status = ed25519_extract_public_key(public_key.data(), keypair.data());
    ASSERT_EQ(status, ED25519_RESULT_OK);

    status = ed25519_verify(signature.data(), public_key.data(), message.data(), message.size());
    ASSERT_EQ(status, ED25519_RESULT_OK);
}

