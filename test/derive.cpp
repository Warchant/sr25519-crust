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
      "28b0ae221c6bb06856b287f60d7ea0d98552ea5a16db16956849aa371db3eb51fd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca3446ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"_unhex;

  auto cc =
      "14416c6963650000000000000000000000000000000000000000000000000000"_unhex;

  std::vector<uint8_t> derived(SR25519_KEYPAIR_SIZE, 0);
  sr25519_derive_keypair_hard(derived.data(), known_kp.data(), cc.data());

  // pubkey = last 32 bytes
  auto actual_pubkey =
      hex(std::vector<uint8_t>{derived.begin() + 64, derived.end()});
  auto expected_pubkey =
      "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"s;

  ASSERT_EQ(actual_pubkey, expected_pubkey);
}

TEST(sr25519, DeriveSoftKnown) {
  auto known_kp =
      "28b0ae221c6bb06856b287f60d7ea0d98552ea5a16db16956849aa371db3eb51fd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca3446ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"_unhex;

  auto cc =
      "0c666f6f00000000000000000000000000000000000000000000000000000000"_unhex;

  std::vector<uint8_t> derived(SR25519_KEYPAIR_SIZE, 0);
  sr25519_derive_keypair_soft(derived.data(), known_kp.data(), cc.data());

  // pubkey = last 32 bytes
  auto actual_pubkey =
      hex(std::vector<uint8_t>{derived.begin() + 64, derived.end()});
  auto expected_pubkey =
      "40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a"s;

  ASSERT_EQ(actual_pubkey, expected_pubkey);
}
