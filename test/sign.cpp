/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <boost/algorithm/hex.hpp>
#include <gtest/gtest.h>
#include <string>

extern "C" {
#include <sr25519/sr25519.h>
}

using std::string_literals::operator""s;
using boost::algorithm::hex;
using boost::algorithm::hex_lower;
using boost::algorithm::unhex;

std::vector<uint8_t> operator"" _unhex(const char *c, size_t s) {
  assert(s % 2 == 0);
  std::vector<uint8_t> v(s / 2, 0);
  unhex(c, c + s, v.data());
  return v;
}

std::vector<uint8_t> operator"" _v(const char *c, size_t s) {
  return std::vector<uint8_t>{c, c + s};
}

TEST(sr25519, PairFromSeed) {
  auto expected =
      "f0106660c3dda23f16daa9ac5b811b963077f5bc0af89f85804f0de8e424f050f98d66f39442506ff947fd911f18c7a7a5da639a63e8d3b4e233f74143d951c1741c08a06f41c596608f6774259bd9043304adfa5d3eea62760bd9be97634d63"s;
  auto seed = "12345678901234567890123456789012"_v;

  std::vector<uint8_t> kp(SR25519_KEYPAIR_SIZE, 0);
  ext_sr_from_seed(kp.data(), seed.data());

  std::string actual;
  hex_lower(kp.begin(), kp.end(), std::back_inserter(actual));
  ASSERT_EQ(actual, expected);
}

TEST(sr25519, SignAndVerify) {
  auto seed = "12345678901234567890123456789012"_v;
  std::vector<uint8_t> kp(SR25519_KEYPAIR_SIZE, 0);
  ext_sr_from_seed(kp.data(), seed.data());

  std::vector<uint8_t> sig(SR25519_SIGNATURE_SIZE, 0);

  // sign seed
  ext_sr_sign(sig.data(), kp.data() + SR25519_SECRET_SIZE, kp.data(),
              seed.data(), (size_t)seed.size());

  bool valid = ext_sr_verify(sig.data(), seed.data(), seed.size(),
                             kp.data() + SR25519_SECRET_SIZE);

  EXPECT_TRUE(valid);
}
