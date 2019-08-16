/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <string>
#include <array>
#include "utils.hpp"

extern "C" {
#include <sr25519/sr25519.h>
}

TEST(VrfTest, Verify) {
  auto keypair = randomKeypair();
  std::array<uint8_t, SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE>
      out_and_proof;

  auto message = "Hello, world!"_v;
  auto limit = std::vector<uint8_t>(32, 0xFF);

  auto res1 =
      sr25519_vrf_sign_if_less(out_and_proof.data(), keypair.data(),
                               message.data(), message.size(), limit.data());
  ASSERT_EQ(res1.result, Sr25519SignatureResult::Ok);
  ASSERT_TRUE(res1.is_less);

  auto res2 = sr25519_vrf_verify(
      keypair.data() + 64, message.data(), message.size(), out_and_proof.data(),
      out_and_proof.data() + SR25519_VRF_OUTPUT_SIZE);
  ASSERT_EQ(res2, Sr25519SignatureResult::Ok);

  out_and_proof[5] += 3;
  auto res3 = sr25519_vrf_verify(
      keypair.data() + 64, message.data(), message.size(), out_and_proof.data(),
      out_and_proof.data() + SR25519_VRF_OUTPUT_SIZE);
  ASSERT_NE(res3, Sr25519SignatureResult::Ok);


}

TEST(VrfTest, ResultNotLess) {
  auto keypair = "915bb406968655c3412df5773c3de3dee9f6da84668b5de8d2f34d0304d20b0bac5ea3a293dfd93859ee64a5b825937753864c19be857f045758dcae10259ba1049b21bb9cb88471b9dadb50b925135cfb291a463043635b58599a2d01b1fd18"_unhex;
  std::array<uint8_t, SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE>
      out_and_proof;

  auto message = "Hello, world!"_v;
  auto limit = std::vector<uint8_t>(32, 0xAA);

  auto res1 =
      sr25519_vrf_sign_if_less(out_and_proof.data(), keypair.data(),
                               message.data(), message.size(), limit.data());
  ASSERT_EQ(res1.result, Sr25519SignatureResult::Ok);
  ASSERT_FALSE(res1.is_less);
}
