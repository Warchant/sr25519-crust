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
using boost::algorithm::unhex;

std::vector<uint8_t> operator"" _unhex(const char *c, size_t s) {
  assert(s % 2 == 0);
  std::vector<uint8_t> v(s / 2, 0);
  unhex(c, c + s, v.data());
  return v;
}

TEST(sr25519, PairFromSeed) {
  std::vector<uint8_t> seed = "12345678901234567890123456789012"_unhex;

  std::vector<uint8_t> kp(SR25519_KEYPAIR_SIZE, 0);
  ext_sr_from_seed(kp.data(), seed.data());
}
