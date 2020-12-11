/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <array>
#include <string>

#include <gtest/gtest.h>

#include "../utils.hpp"
#include "transcript.hpp"

extern "C" {
#include <schnorrkel/schnorrkel.h>
}

TEST(VrfTest, Verify) {
  auto keypair = randomKeypair(SR25519_KEYPAIR_SIZE, sr25519_keypair_from_seed);
  std::array<uint8_t, SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE>
      out_and_proof {};

  auto message = "Hello, world!"_v;
  auto limit = std::vector<uint8_t>(16, 0xFF);

  auto res1 =
      sr25519_vrf_sign_if_less(out_and_proof.data(), keypair.data(),
                               message.data(), message.size(), limit.data());
  ASSERT_EQ(res1.result, SR25519_SIGNATURE_RESULT_OK);
  ASSERT_TRUE(res1.is_less);

  auto res2 = sr25519_vrf_verify(
      keypair.data() + 64, message.data(), message.size(), out_and_proof.data(),
      out_and_proof.data() + SR25519_VRF_OUTPUT_SIZE, limit.data());
  ASSERT_EQ(res2.result, SR25519_SIGNATURE_RESULT_OK);
  ASSERT_TRUE(res2.is_less);

  out_and_proof[5] += 3;
  auto res3 = sr25519_vrf_verify(
      keypair.data() + 64, message.data(), message.size(), out_and_proof.data(),
      out_and_proof.data() + SR25519_VRF_OUTPUT_SIZE, limit.data());
  ASSERT_NE(res3.result, SR25519_SIGNATURE_RESULT_OK);
}

TEST(VrfTest, ResultNotLess) {
  auto keypair =
      "915bb406968655c3412df5773c3de3dee9f6da84668b5de8d2f34d0304d20b0bac5ea3a293dfd93859ee64a5b825937753864c19be857f045758dcae10259ba1049b21bb9cb88471b9dadb50b925135cfb291a463043635b58599a2d01b1fd18"_unhex;
  std::array<uint8_t, SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE>
      out_and_proof {};

  auto message = "Hello, world!"_v;
  auto limit = std::vector<uint8_t>(16, 0x55);

  auto res1 =
      sr25519_vrf_sign_if_less(out_and_proof.data(), keypair.data(),
                               message.data(), message.size(), limit.data());
  ASSERT_EQ(res1.result, SR25519_SIGNATURE_RESULT_OK);
  EXPECT_FALSE(res1.is_less);
}

TEST(VrfTest, SignAndCheck) {
  auto keypair =
      "915bb406968655c3412df5773c3de3dee9f6da84668b5de8d2f34d0304d20b0bac5ea3a293dfd93859ee64a5b825937753864c19be857f045758dcae10259ba1049b21bb9cb88471b9dadb50b925135cfb291a463043635b58599a2d01b1fd18"_unhex;
  std::array<uint8_t, SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE>
      out_and_proof {};

  auto message = "Hello, world!"_v;
  auto limit = std::vector<uint8_t>(16, 0xAA);

  auto res1 =
      sr25519_vrf_sign_if_less(out_and_proof.data(), keypair.data(),
                               message.data(), message.size(), limit.data());
  ASSERT_EQ(res1.result, SR25519_SIGNATURE_RESULT_OK);
  EXPECT_TRUE(res1.is_less);
}

template <size_t MsgBufSize>
Strobe128 makeTranscript(std::string_view message) {
  primitives::Transcript t;
  t.initialize({'B', 'A', 'B', 'E'});
  char msg_buf[MsgBufSize];
  std::fill_n(msg_buf, MsgBufSize, 0);
  std::memcpy(msg_buf, message.data(), message.size());
  t.append_message({'m', 'e', 's', 's', 'a', 'g', 'e'}, msg_buf);

  Strobe128 strobe;
  std::memcpy(strobe.state, t.data().data(), t.data().size());
  strobe.pos = t.state().current_position;
  strobe.cur_flags = t.state().current_state;
  strobe.pos_begin = t.state().begin_position;
  return strobe;
}

TEST(VrfTest, SignAndVerifyTranscript) {
  auto keypair =
      "915bb406968655c3412df5773c3de3dee9f6da84668b5de8d2f34d0304d20b0bac5ea3a293dfd93859ee64a5b825937753864c19be857f045758dcae10259ba1049b21bb9cb88471b9dadb50b925135cfb291a463043635b58599a2d01b1fd18"_unhex;
  std::array<uint8_t, SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE>
      out_and_proof {};

  auto message = "Hello, world!"s;
  auto limit = std::vector<uint8_t>(16, 0xAA);

  auto strobe1 = makeTranscript<14>(message);

  auto res1 =
      sr25519_vrf_sign_transcript(out_and_proof.data(), keypair.data(),
                                  &strobe1, limit.data());
  ASSERT_EQ(res1.result, SR25519_SIGNATURE_RESULT_OK);
  bool less = res1.is_less;

  auto strobe2 = makeTranscript<14>(message);

  auto res2 = sr25519_vrf_verify_transcript(
      keypair.data() + 64, &strobe2, out_and_proof.data(),
      out_and_proof.data() + SR25519_VRF_OUTPUT_SIZE, limit.data());
  ASSERT_EQ(res2.result, SR25519_SIGNATURE_RESULT_OK);
  ASSERT_EQ(less, res2.is_less);

}
