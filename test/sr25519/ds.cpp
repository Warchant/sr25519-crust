/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../utils.hpp"
#include <gtest/gtest.h>

extern "C" {
#include <schnorrkel/schnorrkel.h>
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

TEST(sr25519, VerifyExisting) {
  auto pub =
      "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"_unhex;
  auto secret = "05d65584630d16cd4af6d0bec10f34bb504a5dcb62dba2122d49f5a663763d0a"_unhex;

  auto msg = "this is a message"_v;
  auto sig =
      "4e172314444b8f820bb54c22e95076f220ed25373e5c178234aa6c211d29271244b947e3ff3418ff6b45fd1df1140c8cbff69fc58ee6dc96df70936a2bb74b82"_unhex;

  ASSERT_EQ(pub.size(), SR25519_PUBLIC_SIZE);
  ASSERT_EQ(sig.size(), SR25519_SIGNATURE_SIZE);
  bool valid = sr25519_verify(sig.data(), msg.data(), msg.size(), pub.data());

  ASSERT_TRUE(valid);
}
