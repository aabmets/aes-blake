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
    for (int x = 0; x < 256; x++) {
        const auto idx = static_cast<uint8_t>(x);
        REQUIRE(aes_sbox[idx] == compute_sbox(idx));
    }
}


TEST_CASE("Computed AES inverse S-box matches hardcoded array", "[aes]") {
    for (int x = 0; x < 256; x++) {
        const auto idx = static_cast<uint8_t>(x);
        const uint8_t s_val = compute_sbox(idx);
        REQUIRE(aes_inv_sbox[s_val] == idx);
    }
}


TEST_CASE("Computed AES encryption T-tables match hardcoded arrays", "[aes]") {
    for (int x = 0; x < 256; x++) {
        const auto idx = static_cast<uint8_t>(x);

        uint32_t t0, t1, t2, t3;
        compute_enc_table_words(idx, &t0, &t1, &t2, &t3, true);

        REQUIRE(Te0[x] == t0);
        REQUIRE(Te1[x] == t1);
        REQUIRE(Te2[x] == t2);
        REQUIRE(Te3[x] == t3);
    }
}


TEST_CASE("Computed AES decryption IMC tables match hardcoded arrays", "[aes]") {
    for (int x = 0; x < 256; x++) {
        const auto idx = static_cast<uint8_t>(x);

        uint32_t t0, t1, t2, t3;
        compute_imc_table_words(idx, &t0, &t1, &t2, &t3, true);

        REQUIRE(IMC0[x] == t0);
        REQUIRE(IMC1[x] == t1);
        REQUIRE(IMC2[x] == t2);
        REQUIRE(IMC3[x] == t3);
    }
}

