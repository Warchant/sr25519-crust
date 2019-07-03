/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "utils.hpp"
#include <gtest/gtest.h>
#include <string>

extern "C" {
#include <sr25519/sr25519.h>
}

TEST(VrfTest, Verify) {
  auto keypair = randomKeypair();
  std::array<uint8_t, SR25519_VRF_OUTPUT_LENGTH + SR25519_VRF_PROOF_LENGTH>
      out_and_proof;

  auto message = "Hello, world!"_v;
  auto limit = std::vector<uint8_t>(32, 0xFF);

  auto res1 =
      sr25519_vrf_sign_if_less(out_and_proof.data(), keypair.data(),
                               message.data(), message.size(), limit.data());
  ASSERT_EQ(res1.err_msg, nullptr) << res1.err_msg;
  ASSERT_TRUE(res1.is_less);

  auto res2 = sr25519_vrf_verify(
      keypair.data() + 64, message.data(), message.size(), out_and_proof.data(),
      out_and_proof.data() + SR25519_VRF_OUTPUT_LENGTH);
  ASSERT_EQ(res2, nullptr) << res2;
}

TEST(VrfTest, ResultNotLess) {
  auto keypair =
      "ddaa6865d6ddf2ac2e7fd9f0e5e407f6408984e39d15a570f18bc964c25a7c0f4741a419260f05ac30c41f1d7a1e187225d2113b3df05ba31fc8e180a52790af4e00706c6bf7e5da937a503b463cc8199ed2317c42ce59909debf89525996650"_unhex;

  std::array<uint8_t, SR25519_VRF_OUTPUT_LENGTH + SR25519_VRF_PROOF_LENGTH>
      out_and_proof;

  auto message = "Hello, world!"_v;
  auto limit = std::vector<uint8_t>(32, 0xAA);

  auto res1 =
      sr25519_vrf_sign_if_less(out_and_proof.data(), keypair.data(),
                               message.data(), message.size(), limit.data());
  ASSERT_EQ(res1.err_msg, nullptr) << res1.err_msg;
  ASSERT_FALSE(res1.is_less);
}
