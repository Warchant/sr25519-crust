/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <boost/algorithm/hex.hpp>
#include <gtest/gtest.h>
#include <string>
#include "utils.hpp"

extern "C" {
#include <sr25519/sr25519.h>
}


struct Case1 {
  std::vector<uint8_t> seed;
  std::string expected_keypair_hex;
};

struct KeypairFromSeed : public ::testing::TestWithParam<Case1> {
  static std::vector<Case1> cases;
};

std::vector<Case1> KeypairFromSeed::cases = {
    {"12345678901234567890123456789012"_v,
     "f0106660c3dda23f16daa9ac5b811b963077f5bc0af89f85804f0de8e424f050f98d66f39442506ff947fd911f18c7a7a5da639a63e8d3b4e233f74143d951c1741c08a06f41c596608f6774259bd9043304adfa5d3eea62760bd9be97634d63"s},
    {"fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"_unhex,
     "28b0ae221c6bb06856b287f60d7ea0d98552ea5a16db16956849aa371db3eb51fd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca3446ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"s}};

TEST_P(KeypairFromSeed, ValidKeypairGenerated) {
  auto [seed, expected] = GetParam();

  std::vector<uint8_t> kp(SR25519_KEYPAIR_SIZE, 0);
  sr25519_keypair_from_seed(kp.data(), seed.data());

  std::string actual = hex(kp);
  ASSERT_EQ(actual, expected);
}

INSTANTIATE_TEST_CASE_P(sr25519, KeypairFromSeed,
                        ::testing::ValuesIn(KeypairFromSeed::cases));
