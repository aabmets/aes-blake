/*
 *   Apache License 2.0
 *
 *   Copyright (c) 2024, Mattias Aabmets
 *
 *   The contents of this file are subject to the terms and conditions defined in the License.
 *   You may not use, modify, or distribute this file except in compliance with the License.
 *
 *   SPDX-License-Identifier: Apache-2.0
 */

#include <catch2/catch_all.hpp>
#include "aes_sbox.h"

namespace {
    // Multiply two numbers in GF(2^8) with the AES polynomial 0x11B
    uint8_t gf_mul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) p ^= a;
            const bool hi = (a & 0x80) != 0;
            a <<= 1;
            if (hi) a ^= 0x1B;
            b >>= 1;
        }
        return p;
    }

    // Multiplicative inverse in GF(2^8)
    uint8_t gf_inv(const uint8_t x) {
        if (!x) return 0;
        uint8_t result = 1;
        uint8_t base = x;
        uint8_t exp = 254; // Since x^(254) equals the inverse in GF(2^8)
        while (exp) {
            if (exp & 1)
                result = gf_mul(result, base);
            base = gf_mul(base, base);
            exp >>= 1;
        }
        return result;
    }

    // Compute AES S-box value for a byte
    uint8_t compute_sbox(const uint8_t x) {
        const uint8_t inv = gf_inv(x);
        uint8_t y = inv;
        y ^= (inv << 1) | (inv >> 7);
        y ^= (inv << 2) | (inv >> 6);
        y ^= (inv << 3) | (inv >> 5);
        y ^= (inv << 4) | (inv >> 4);
        y ^= 0x63;
        return y;
    }
}


TEST_CASE("Computed AES S-box matches hardcoded array", "[sbox]") {
    for (int i = 0; i < 256; ++i) {
        const auto idx = static_cast<uint8_t>(i);
        REQUIRE(aes_sbox[idx] == compute_sbox(idx));
    }
}


TEST_CASE("Computed AES inverse S-box matches hardcoded array", "[sbox]") {
    for (int i = 0; i < 256; ++i) {
        const auto idx = static_cast<uint8_t>(i);
        const uint8_t s_val = compute_sbox(idx);
        REQUIRE(aes_inv_sbox[s_val] == idx);
    }
}
