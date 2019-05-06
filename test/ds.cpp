/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "utils.hpp"
#include <gtest/gtest.h>

extern "C" {
#include <sr25519/sr25519.h>
}

TEST(sr25519, SignAndVerifyValid) {
  auto kp = randomKeypair();
  auto msg = "hello world"_v;

  std::vector<uint8_t> sig(SR25519_SIGNATURE_SIZE, 0);

  // sign seed
  sr25519_sign(sig.data(), kp.data() + SR25519_SECRET_SIZE, kp.data(),
              msg.data(), (size_t)msg.size());

  bool valid = sr25519_verify(sig.data(), msg.data(), msg.size(),
                             kp.data() + SR25519_SECRET_SIZE);

  EXPECT_TRUE(valid);
}

TEST(sr25519, SignAndVerifyInvalid) {
  auto kp = randomKeypair(0);
  auto msg = "hello world"_v;

  std::vector<uint8_t> sig(SR25519_SIGNATURE_SIZE, 0);

  // sign seed
  sr25519_sign(sig.data(), kp.data() + SR25519_SECRET_SIZE, kp.data(),
              msg.data(), (size_t)msg.size());

  // break signature
  sig[0] = 0;

  bool valid = sr25519_verify(sig.data(), msg.data(), msg.size(),
                             kp.data() + SR25519_SECRET_SIZE);

  EXPECT_FALSE(valid);
}

TEST(sr25519, VerifyExisting){
  auto pub = "741c08a06f41c596608f6774259bd9043304adfa5d3eea62760bd9be97634d63"_unhex;
  auto msg = "this is a message"_v;
  auto sig = "decef12cf20443e7c7a9d406c237e90bcfcf145860722622f92ebfd5eb4b5b3990b6443934b5cba8f925a0ae75b3a77d35b8490cbb358dd850806e58eaf72904"_unhex;

  bool valid = sr25519_verify(sig.data(), msg.data(), msg.size(), pub.data());

  ASSERT_TRUE(valid);
}
