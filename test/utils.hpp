/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SR25519CRUST_UTILS_HPP
#define SR25519CRUST_UTILS_HPP

#include <algorithm>
#include <cassert>
#include <iomanip>
#include <random>
#include <sstream>
#include <vector>


using std::string_literals::operator ""s;

inline std::vector<uint8_t>
randomKeypair(size_t keypair_length, std::function<void(uint8_t *, const uint8_t *)> keypair_from_seed,
              size_t initseed = std::random_device()()) {
    std::mt19937 gen(initseed);
    std::vector<uint8_t> seed(keypair_length, 0);
    std::generate(seed.begin(), seed.end(), [&gen]() { return (uint8_t) gen(); });

    std::vector<uint8_t> kp(keypair_length, 0);
    keypair_from_seed(kp.data(), seed.data());

    return kp;
}

inline std::vector<uint8_t> operator "" _unhex(const char *c, size_t s) {
    assert(s % 2 == 0);

    std::string hex{c, c + s};
    std::vector<uint8_t> v;

    int len = hex.length();
    std::string newString;
    for (auto i = 0; i < len; i += 2) {
        std::string byte = hex.substr(i, 2);
        char chr = (char) strtol(byte.c_str(), nullptr, 16);
        v.push_back(chr);
    }

    return v;
}

inline std::vector<uint8_t> operator "" _v(const char *c, size_t s) {
    return std::vector<uint8_t>{c, c + s};
}

template <typename T>
inline std::string hex(const T &v) {
    assert(!v.empty());
    static auto alphabet = "0123456789abcdef";
    std::string out(v.size() * 2, 0);

    for (auto i = 0u; i < v.size(); i++) {
        out[i * 2] = alphabet[v[i] >> 4];
        out[i * 2 + 1] = alphabet[v[i] & 0x0F];
    }

    return out;
}

#endif // SR25519CRUST_UTILS_HPP
