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
#include "aes_tables.h"
#include "aes_utils.h"


TEST_CASE("Computed AES S-box matches hardcoded array", "[aes]") {
    for (int i = 0; i < 256; ++i) {
        const auto idx = static_cast<uint8_t>(i);
        REQUIRE(aes_sbox[idx] == compute_sbox(idx));
    }
}


TEST_CASE("Computed AES inverse S-box matches hardcoded array", "[aes]") {
    for (int i = 0; i < 256; ++i) {
        const auto idx = static_cast<uint8_t>(i);
        const uint8_t s_val = compute_sbox(idx);
        REQUIRE(aes_inv_sbox[s_val] == idx);
    }
}


TEST_CASE("Computed AES encryption T-tables match hardcoded arrays", "[aes]") {
    for (int i = 0; i < 256; i++) {
        uint32_t t0, t1, t2, t3;
        compute_enc_table_words(i, &t0, &t1, &t2, &t3, true);

        REQUIRE(Te0[i] == t0);
        REQUIRE(Te1[i] == t1);
        REQUIRE(Te2[i] == t2);
        REQUIRE(Te3[i] == t3);
    }
}
