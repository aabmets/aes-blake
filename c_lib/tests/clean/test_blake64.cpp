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
#include "blake64.h"


TEST_CASE("rotr64: rotating by 0 returns the original value", "[rotr64]") {
    REQUIRE(rotr64(0x0000000000000000ULL, 0) == 0x0000000000000000ULL);
    REQUIRE(rotr64(0x0123456789ABCDEFULL, 0) == 0x0123456789ABCDEFULL);
}


TEST_CASE("rotr64: basic rotations", "[rotr64]") {
    SECTION("rotate a single bit from LSB to MSB") {
        uint64_t x = 0x0000000000000001ULL; // bit0 set
        REQUIRE(rotr64(x, 1) == 0x8000000000000000ULL);
        REQUIRE(rotr64(x, 2) == 0x4000000000000000ULL);
        REQUIRE(rotr64(x, 63) == 0x0000000000000002ULL);
    }

    SECTION("rotate an arbitrary pattern by 16") {
        uint64_t x = 0x1122334455667788ULL;
        // Expected: 0x7788112233445566
        REQUIRE(rotr64(x, 16) == 0x7788112233445566ULL);
    }

    SECTION("rotate a pattern by half the word size") {
        uint64_t x = 0xF0F0F0F0F0F0F0F0ULL;
        // Rotating by 32 should swap high and low 32-bit halves
        REQUIRE(rotr64(x, 32) == 0xF0F0F0F0F0F0F0F0ULL);
    }

    SECTION("rotate by various amounts on 0xAAAAAAAAAAAAAAAA") {
        uint64_t x = 0xAAAAAAAAAAAAAAAAULL; // alternating bits: 1010...
        REQUIRE(rotr64(x, 1)  == 0x5555555555555555ULL); // complement pattern
        REQUIRE(rotr64(x, 7)  == 0x5555555555555555ULL);
        REQUIRE(rotr64(x, 2)  == 0xAAAAAAAAAAAAAAAAULL); // same pattern
        REQUIRE(rotr64(x, 62) == 0xAAAAAAAAAAAAAAAAULL);
    }
}


TEST_CASE("permute64: zeros remain zeros", "[permute64]") {
    uint64_t m[16] = {0};
    permute64(m);
    for (const unsigned long long i : m) {
        REQUIRE(i == 0ULL);
    }
}


TEST_CASE("permute64: identity mapping yields expected schedule (cast to uint64_t)", "[permute64]") {
    uint64_t m[16];
    for (uint64_t i = 0; i < 16; ++i) {
        m[i] = i;
    }
    permute64(m);

    const uint64_t expected[16] = {
        2ULL, 6ULL, 3ULL, 10ULL, 7ULL,  0ULL,  4ULL, 13ULL,
        1ULL, 11ULL, 12ULL,  5ULL, 9ULL, 14ULL, 15ULL,  8ULL
    };
    for (int i = 0; i < 16; ++i) {
        REQUIRE(m[i] == expected[i]);
    }
}