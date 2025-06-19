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
#include "csprng.h"
#include "masking.h"


template<typename T>
struct dom_traits;

template<>
struct dom_traits<uint8_t> {
    using masked_type = masked_uint8_t;
    static masked_type* dom_mask(const uint8_t value, const domain_t domain)
        { return dom_mask_u8(value, domain); }
    static uint8_t dom_unmask(masked_type* mv)
        { return dom_unmask_u8(mv); }
    static void dom_conv_btoa(masked_type* mv)
        { dom_conv_btoa_u8(mv); }
    static void dom_conv_atob(masked_type* mv)
        { dom_conv_atob_u8(mv); }
};

template<>
struct dom_traits<uint32_t> {
    using masked_type = masked_uint32_t;
    static masked_type* dom_mask(const uint32_t value, const domain_t domain)
        { return dom_mask_u32(value, domain); }
    static uint32_t dom_unmask(masked_type* mv)
        { return dom_unmask_u32(mv); }
    static void dom_conv_btoa(masked_type* mv)
        { dom_conv_btoa_u32(mv); }
    static void dom_conv_atob(masked_type* mv)
        { dom_conv_atob_u32(mv); }
};

template<>
struct dom_traits<uint64_t> {
    using masked_type = masked_uint64_t;
    static masked_type* dom_mask(const uint64_t value, const domain_t domain)
        { return dom_mask_u64(value, domain); }
    static uint64_t dom_unmask(masked_type* mv)
        { return dom_unmask_u64(mv); }
    static void dom_conv_btoa(masked_type* mv)
        { dom_conv_btoa_u64(mv); }
    static void dom_conv_atob(masked_type* mv)
        { dom_conv_atob_u64(mv); }
};


TEMPLATE_TEST_CASE(
        "2nd-order DOM converter functions work correctly", "[unittest][dom]",
        uint8_t, uint32_t, uint64_t
) {
    for (int i = 0; i < 100; i++) {
        TestType expected[1];
        csprng_read_array((uint8_t*)(expected), sizeof(expected));

        // Mask expected value with boolean domain
        auto* mv = dom_traits<TestType>::dom_mask(expected[0], DOMAIN_BOOLEAN);
        REQUIRE(mv->domain == DOMAIN_BOOLEAN);

        dom_traits<TestType>::dom_conv_btoa(mv);

        // Check unmasking from the arithmetic domain
        TestType manually_unmasked = mv->shares[0] - mv->shares[1] - mv->shares[2];
        REQUIRE(manually_unmasked == static_cast<TestType>(expected[0]));
        REQUIRE(mv->domain == DOMAIN_ARITHMETIC);

        dom_traits<TestType>::dom_conv_atob(mv);

        // Check unmasking back in the boolean domain
        TestType func_unmasked = dom_traits<TestType>::dom_unmask(mv);
        REQUIRE(func_unmasked == static_cast<TestType>(expected[0]));
        REQUIRE(mv->domain == DOMAIN_BOOLEAN);
    }
}
