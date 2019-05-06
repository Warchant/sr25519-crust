/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SR25519CRUST_UTILS_HPP
#define SR25519CRUST_UTILS_HPP

#include <boost/algorithm/hex.hpp>
#include <random>
#include <vector>

extern "C" {
#include <sr25519/sr25519.h>
};

using std::string_literals::operator""s;
namespace b = boost::algorithm;

inline std::vector<uint8_t>
randomKeypair(size_t initseed = std::random_device()()) {
  std::mt19937 gen(initseed);
  std::vector<uint8_t> seed(SR25519_SEED_SIZE, 0);
  std::generate(seed.begin(), seed.end(), [&gen]() { return (uint8_t)gen(); });

  std::vector<uint8_t> kp(SR25519_KEYPAIR_SIZE, 0);
  sr25519_keypair_from_seed(kp.data(), seed.data());

  return kp;
}

inline std::vector<uint8_t> operator"" _unhex(const char *c, size_t s) {
  assert(s % 2 == 0);
  std::vector<uint8_t> v(s / 2, 0);
  b::unhex(c, c + s, v.data());
  return v;
}

inline std::vector<uint8_t> operator"" _v(const char *c, size_t s) {
  return std::vector<uint8_t>{c, c + s};
}

inline std::string hex(std::vector<uint8_t> v) {
  assert(!v.empty());
  std::string h(v.size() * 2, 0);
  b::hex_lower(v.begin(), v.end(), h.begin());
  return h;
}

#endif // SR25519CRUST_UTILS_HPP
