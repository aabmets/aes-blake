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

#define DEFINE_DOM_TRAITS(TYPE, SHORT_TYPE)                                     \
template<>                                                                      \
struct dom_traits<TYPE> {                                                       \
    using mskd_t = masked_##TYPE;                                               \
    static mskd_t* dom_mask(const TYPE value, const domain_t domain)            \
        { return dom_mask_##SHORT_TYPE(value, domain); }                        \
    static TYPE dom_unmask(mskd_t* mv)                                          \
        { return dom_unmask_##SHORT_TYPE(mv); }                                 \
    static void dom_conv_btoa(mskd_t* mv)                                       \
        { dom_conv_btoa_##SHORT_TYPE(mv); }                                     \
    static void dom_conv_atob(mskd_t* mv)                                       \
        { dom_conv_atob_##SHORT_TYPE(mv); }                                     \
};                                                                              \

DEFINE_DOM_TRAITS(uint8_t, u8)
DEFINE_DOM_TRAITS(uint32_t, u32)
DEFINE_DOM_TRAITS(uint64_t, u64)

#undef DEFINE_DOM_TRAITS


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
