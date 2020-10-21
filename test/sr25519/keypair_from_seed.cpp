/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../utils.hpp"
#include <gtest/gtest.h>
#include <string>

extern "C" {
#include <schnorrkel/schnorrkel.h>
}

struct Case1 {
  std::vector<uint8_t> seed;
  std::string expected_keypair_hex;
};

struct KeypairFromSeed : public ::testing::TestWithParam<Case1> {
  static std::vector<Case1> cases;
};

std::vector<Case1> KeypairFromSeed::cases = {
    {std::vector<uint8_t>(32, 0),
     "caa835781b15c7706f65b71f7a58c807ab360faed6440fb23e0f4c52e930de0a0a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3def12e42f3e487e9b14095aa8d5cc16a33491f1b50dadcf8811d1480f3fa8627"s},
    {"12345678901234567890123456789012"_v,
     "1ec20c6cb85bf4c7423b95752b70c312e6ae9e5701ffb310f0a9019d9c041e0af98d66f39442506ff947fd911f18c7a7a5da639a63e8d3b4e233f74143d951c1741c08a06f41c596608f6774259bd9043304adfa5d3eea62760bd9be97634d63"s},
    {"fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"_unhex,
     "05d65584630d16cd4af6d0bec10f34bb504a5dcb62dba2122d49f5a663763d0afd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca3446ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"s}};

TEST_P(KeypairFromSeed, ValidKeypairGenerated) {
  auto [seed, expected] = GetParam();

  std::vector<uint8_t> kp(SR25519_KEYPAIR_SIZE, 0);
  sr25519_keypair_from_seed(kp.data(), seed.data());

  std::string actual = hex(kp);
  ASSERT_EQ(actual, expected);
}

INSTANTIATE_TEST_CASE_P(sr25519, KeypairFromSeed,
                        ::testing::ValuesIn(KeypairFromSeed::cases));
