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
#include "masking.h"
#include "csprng.h"


TEST_CASE("Second-order DOM OR 8bit gadget computes correctly", "[unittest][dom]") {
    constexpr unsigned int iterations = 100;

    uint8_t unmasked_x[iterations];
    uint8_t unmasked_y[iterations];
    uint8_t masked_x[N_SHARES];
    uint8_t masked_y[N_SHARES];

    csprng_read_array(unmasked_x, sizeof(unmasked_x));
    csprng_read_array(unmasked_y, sizeof(unmasked_x));

    for (int i = 0; i < iterations; ++i) {
        const uint8_t um_x = unmasked_x[i];
        const uint8_t um_y = unmasked_y[i];

        dom_mask8(um_x, masked_x);
        dom_mask8(um_y, masked_y);

        REQUIRE(dom_unmask8(masked_x) == um_x);
        REQUIRE(dom_unmask8(masked_y) == um_y);

        uint8_t out[N_SHARES];
        dom_bw_or8(masked_x, masked_y, out);

        const uint8_t expected_result = um_x | um_y;
        const uint8_t actual_result = dom_unmask8(out);
        REQUIRE(actual_result == expected_result);
    }
}


TEST_CASE("Second-order DOM OR 32bit gadget computes correctly", "[unittest][dom]") {
    constexpr unsigned int iterations = 100;

    uint32_t unmasked_x[iterations];
    uint32_t unmasked_y[iterations];
    uint32_t masked_x[N_SHARES];
    uint32_t masked_y[N_SHARES];

    auto *um_x_ptr = reinterpret_cast<uint8_t*>(unmasked_x);
    auto *um_y_ptr = reinterpret_cast<uint8_t*>(unmasked_y);

    csprng_read_array(um_x_ptr, sizeof(unmasked_x));
    csprng_read_array(um_y_ptr, sizeof(unmasked_y));

    for (int i = 0; i < iterations; ++i) {
        const uint32_t um_x = unmasked_x[i];
        const uint32_t um_y = unmasked_y[i];

        dom_mask32(um_x, masked_x);
        dom_mask32(um_y, masked_y);

        REQUIRE(dom_unmask32(masked_x) == um_x);
        REQUIRE(dom_unmask32(masked_y) == um_y);

        uint32_t out[N_SHARES];
        dom_bw_or32(masked_x, masked_y, out);

        const uint32_t expected_result = um_x | um_y;
        const uint32_t actual_result = dom_unmask32(out);
        REQUIRE(actual_result == expected_result);
    }
}


TEST_CASE("Second-order DOM OR 64bit gadget computes correctly", "[unittest][dom]") {
    constexpr unsigned int iterations = 100;

    uint64_t unmasked_x[iterations];
    uint64_t unmasked_y[iterations];
    uint64_t masked_x[N_SHARES];
    uint64_t masked_y[N_SHARES];

    auto *um_x_ptr = reinterpret_cast<uint8_t*>(unmasked_x);
    auto *um_y_ptr = reinterpret_cast<uint8_t*>(unmasked_y);

    csprng_read_array(um_x_ptr, sizeof(unmasked_x));
    csprng_read_array(um_y_ptr, sizeof(unmasked_y));

    for (int i = 0; i < iterations; ++i) {
        const uint64_t um_x = unmasked_x[i];
        const uint64_t um_y = unmasked_y[i];

        dom_mask64(um_x, masked_x);
        dom_mask64(um_y, masked_y);

        REQUIRE(dom_unmask64(masked_x) == um_x);
        REQUIRE(dom_unmask64(masked_y) == um_y);

        uint64_t out[N_SHARES];
        dom_bw_or64(masked_x, masked_y, out);

        const uint64_t expected_result = um_x | um_y;
        const uint64_t actual_result = dom_unmask64(out);
        REQUIRE(actual_result == expected_result);
    }
}