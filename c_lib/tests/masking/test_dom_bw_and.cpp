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


TEST_CASE("Second-order DOM AND 8bit gadget computes correctly", "[unittest][dom]") {
    constexpr unsigned int iterations = 100;

    uint8_t unmasked_x[100];
    uint8_t unmasked_y[100];
    uint8_t masked_x[3];
    uint8_t masked_y[3];

    csprng_read_array(unmasked_x, 100);
    csprng_read_array(unmasked_y, 100);

    for (int i = 0; i < iterations; ++i) {
        const uint8_t um_x = unmasked_x[i];
        const uint8_t um_y = unmasked_y[i];
        const uint8_t expected_result = um_x & um_y;

        dom_mask8(um_x, masked_x);
        dom_mask8(um_y, masked_y);

        REQUIRE((masked_x[0] ^ masked_x[1] ^ masked_x[2]) == um_x);
        REQUIRE((masked_y[0] ^ masked_y[1] ^ masked_y[2]) == um_y);

        uint8_t out_1[3];
        dom_bw_and8(masked_x, masked_y, out_1);

        const uint8_t actual_result_1 = out_1[0] ^ out_1[1] ^ out_1[2];
        REQUIRE(actual_result_1 == expected_result);

        uint8_t out_2[3];
        dom_bw_and8(masked_x, masked_y, out_2);

        const uint8_t actual_result_2 = out_2[0] ^ out_2[1] ^ out_2[2];
        REQUIRE(actual_result_2 == expected_result);
    }
}


TEST_CASE("Second-order DOM AND 32bit gadget computes correctly", "[unittest][dom]") {
    constexpr unsigned int iterations = 100;

    uint32_t unmasked_x[100];
    uint32_t unmasked_y[100];
    uint32_t masked_x[3];
    uint32_t masked_y[3];

    auto *um_x_ptr = reinterpret_cast<uint8_t*>(unmasked_x);
    auto *um_y_ptr = reinterpret_cast<uint8_t*>(unmasked_y);

    csprng_read_array(um_x_ptr, sizeof(unmasked_x));
    csprng_read_array(um_y_ptr, sizeof(unmasked_y));

    for (int i = 0; i < iterations; ++i) {
        const uint32_t um_x = unmasked_x[i];
        const uint32_t um_y = unmasked_y[i];
        const uint32_t expected_result = um_x & um_y;

        dom_mask32(um_x, masked_x);
        dom_mask32(um_y, masked_y);

        REQUIRE((masked_x[0] ^ masked_x[1] ^ masked_x[2]) == um_x);
        REQUIRE((masked_y[0] ^ masked_y[1] ^ masked_y[2]) == um_y);

        uint32_t out_1[3];
        dom_bw_and32(masked_x, masked_y, out_1);

        const uint32_t actual_result_1 = out_1[0] ^ out_1[1] ^ out_1[2];
        REQUIRE(actual_result_1 == expected_result);

        uint32_t out_2[3];
        dom_bw_and32(masked_x, masked_y, out_2);

        const uint32_t actual_result_2 = out_2[0] ^ out_2[1] ^ out_2[2];
        REQUIRE(actual_result_2 == expected_result);
    }
}


TEST_CASE("Second-order DOM AND 64bit gadget computes correctly", "[unittest][dom]") {
    constexpr unsigned int iterations = 100;

    uint64_t unmasked_x[100];
    uint64_t unmasked_y[100];
    uint64_t masked_x[3];
    uint64_t masked_y[3];

    auto *um_x_ptr = reinterpret_cast<uint8_t*>(unmasked_x);
    auto *um_y_ptr = reinterpret_cast<uint8_t*>(unmasked_y);

    csprng_read_array(um_x_ptr, sizeof(unmasked_x));
    csprng_read_array(um_y_ptr, sizeof(unmasked_y));

    for (int i = 0; i < iterations; ++i) {
        const uint64_t um_x = unmasked_x[i];
        const uint64_t um_y = unmasked_y[i];
        const uint64_t expected_result = um_x & um_y;

        dom_mask64(um_x, masked_x);
        dom_mask64(um_y, masked_y);

        REQUIRE((masked_x[0] ^ masked_x[1] ^ masked_x[2]) == um_x);
        REQUIRE((masked_y[0] ^ masked_y[1] ^ masked_y[2]) == um_y);

        uint64_t out_1[3];
        dom_bw_and64(masked_x, masked_y, out_1);

        const uint64_t actual_result_1 = out_1[0] ^ out_1[1] ^ out_1[2];
        REQUIRE(actual_result_1 == expected_result);

        uint64_t out_2[3];
        dom_bw_and64(masked_x, masked_y, out_2);

        const uint64_t actual_result_2 = out_2[0] ^ out_2[1] ^ out_2[2];
        REQUIRE(actual_result_2 == expected_result);
    }
}
