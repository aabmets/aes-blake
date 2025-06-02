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
#include "blake32.h"


TEST_CASE("rotr32: rotating by 0 returns the original value", "[rotr32]") {
    REQUIRE(rotr32(0x00000000u, 0) == 0x00000000u);
    REQUIRE(rotr32(0xDEADBEEFu, 0) == 0xDEADBEEFu);
}


TEST_CASE("rotr32: basic rotations", "[rotr32]") {
    SECTION("rotate a single bit from LSB to MSB") {
        uint32_t x = 0x00000001u; // bit0 set
        REQUIRE(rotr32(x, 1) == 0x80000000u);
        REQUIRE(rotr32(x, 2) == 0x40000000u);
        REQUIRE(rotr32(x, 31) == 0x00000002u);
    }

    SECTION("rotate an arbitrary pattern by 8") {
        uint32_t x = 0x12345678u;
        // Expected: 0x78123456
        REQUIRE(rotr32(x, 8) == 0x78123456u);
    }

    SECTION("rotate a pattern by half the word size") {
        uint32_t x = 0xF0F0F0F0u;
        // Rotating by 16 should swap high and low 16-bit halves
        REQUIRE(rotr32(x, 16) == 0xF0F0F0F0u);
    }

    SECTION("rotate by various amounts on 0xAAAAAAAA") {
        uint32_t x = 0xAAAAAAAAu; // alternating bits: 1010...
        REQUIRE(rotr32(x, 1)  == 0x55555555u); // complement pattern
        REQUIRE(rotr32(x, 7)  == 0x55555555u);
        REQUIRE(rotr32(x, 2)  == 0xAAAAAAAAu); // same pattern
        REQUIRE(rotr32(x, 30) == 0xAAAAAAAAu);
    }
}


TEST_CASE("permute32: zeros remain zeros", "[permute32]") {
    uint32_t m[16] = {0};
    permute32(m);
    for (const unsigned int i : m) {
        REQUIRE(i == 0u);
    }
}


TEST_CASE("permute32: identity mapping yields expected schedule", "[permute32]") {
    uint32_t m[16];
    for (uint32_t i = 0; i < 16; ++i) {
        m[i] = i;
    }
    permute32(m);

    const uint32_t expected[16] = {
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
    };
    for (int i = 0; i < 16; ++i) {
        REQUIRE(m[i] == expected[i]);
    }
}