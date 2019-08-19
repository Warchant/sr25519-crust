/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "utils.hpp"
#include <gtest/gtest.h>

extern "C" {
#include <sr25519/sr25519.h>
}

TEST(sr25519, DeriveHardKnown) {
  auto known_kp =
      "4c1250e05afcd79e74f6c035aee10248841090e009b6fd7ba6a98d5dc743250cafa4b32c608e3ee2ba624850b3f14c75841af84b16798bf1ee4a3875aa37a2cee661e416406384fe1ca091980958576d2bff7c461636e9f22c895f444905ea1f"_unhex;

  auto cc =
      "14416c6963650000000000000000000000000000000000000000000000000000"_unhex;

  std::vector<uint8_t> derived(SR25519_KEYPAIR_SIZE, 0);
  sr25519_derive_keypair_hard(derived.data(), known_kp.data(), cc.data());

  // pubkey = last 32 bytes
  auto actual_pubkey =
      hex(std::vector<uint8_t>{derived.begin() + 64, derived.end()});
  auto expected_pubkey =
      "d8db757f04521a940f0237c8a1e44dfbe0b3e39af929eb2e9e257ba61b9a0a1a"s;

  ASSERT_EQ(actual_pubkey, expected_pubkey);
}

TEST(sr25519, DeriveSoftKnown) {
  auto known_kp =
      "4c1250e05afcd79e74f6c035aee10248841090e009b6fd7ba6a98d5dc743250cafa4b32c608e3ee2ba624850b3f14c75841af84b16798bf1ee4a3875aa37a2cee661e416406384fe1ca091980958576d2bff7c461636e9f22c895f444905ea1f"_unhex;

  auto cc =
      "0c666f6f00000000000000000000000000000000000000000000000000000000"_unhex;

  std::vector<uint8_t> derived(SR25519_KEYPAIR_SIZE, 0);
  sr25519_derive_keypair_soft(derived.data(), known_kp.data(), cc.data());

  // pubkey = last 32 bytes
  auto actual_pubkey =
      hex(std::vector<uint8_t>{derived.begin() + 64, derived.end()});
  auto expected_pubkey =
      "b21e5aabeeb35d6a1bf76226a6c65cd897016df09ef208243e59eed2401f5357"s;

  ASSERT_EQ(actual_pubkey, expected_pubkey);
}
