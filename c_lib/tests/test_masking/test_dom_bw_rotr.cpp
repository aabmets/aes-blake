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
#include <limits.h>
#include "masking.h"
#include "csprng.h"


TEST_CASE("Second-order DOM ROTR 8bit gadget computes correctly", "[unittest][dom]") {
    constexpr unsigned int iterations = 100;
    const uint8_t bit_count = CHAR_BIT * sizeof(uint8_t);
    const uint8_t shift = 3;

    uint8_t unmasked_x[iterations];
    uint8_t masked_x[N_SHARES];

    csprng_read_array(unmasked_x, iterations);

    for (int i = 0; i < iterations; ++i) {
        const uint8_t um_x = unmasked_x[i];

        dom_mask8(um_x, masked_x);

        REQUIRE(dom_unmask8(masked_x) == um_x);

        uint8_t out[N_SHARES];
        dom_bw_rotr8(masked_x, out, shift);

        const uint8_t expected_result = um_x >> shift | um_x << (bit_count - shift);
        const uint8_t actual_result = dom_unmask8(out);
        REQUIRE(actual_result == expected_result);
    }
}


TEST_CASE("Second-order DOM ROTR 32bit gadget computes correctly", "[unittest][dom]") {
    constexpr unsigned int iterations = 100;
    const uint8_t bit_count = CHAR_BIT * sizeof(uint32_t);
    const uint8_t shift = 17;

    uint32_t unmasked_x[iterations];
    uint32_t masked_x[N_SHARES];

    auto *um_x_ptr = reinterpret_cast<uint8_t*>(unmasked_x);

    csprng_read_array(um_x_ptr, sizeof(unmasked_x));

    for (int i = 0; i < iterations; ++i) {
        const uint32_t um_x = unmasked_x[i];

        dom_mask32(um_x, masked_x);

        REQUIRE(dom_unmask32(masked_x) == um_x);

        uint32_t out[N_SHARES];
        dom_bw_rotr32(masked_x, out, shift);

        const uint32_t expected_result = um_x >> shift | um_x << (bit_count - shift);
        const uint32_t actual_result = dom_unmask32(out);
        REQUIRE(actual_result == expected_result);
    }
}


TEST_CASE("Second-order DOM ROTR 64bit gadget computes correctly", "[unittest][dom]") {
    constexpr unsigned int iterations = 100;
    const uint8_t bit_count = CHAR_BIT * sizeof(uint64_t);
    const uint8_t shift = 47;

    uint64_t unmasked_x[iterations];
    uint64_t masked_x[N_SHARES];

    auto *um_x_ptr = reinterpret_cast<uint8_t*>(unmasked_x);

    csprng_read_array(um_x_ptr, sizeof(unmasked_x));

    for (int i = 0; i < iterations; ++i) {
        const uint64_t um_x = unmasked_x[i];

        dom_mask64(um_x, masked_x);

        REQUIRE(dom_unmask64(masked_x) == um_x);

        uint64_t out[N_SHARES];
        dom_bw_rotr64(masked_x, out, shift);

        const uint64_t expected_result = um_x >> shift | um_x << (bit_count - shift);
        const uint64_t actual_result = dom_unmask64(out);
        REQUIRE(actual_result == expected_result);
    }
}