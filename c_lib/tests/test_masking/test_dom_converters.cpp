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

#define DEFINE_DOM_TRAITS(TYPE, SHORT)                                                                                  \
template<>                                                                                                              \
struct dom_traits<TYPE> {                                                                                               \
    using mskd_t = masked_##TYPE;                                                                                       \
                                                                                                                        \
    static void      dom_free        (mskd_t *mv)                      { dom_free_##SHORT(mv); }                        \
    static mskd_t*   dom_mask        (TYPE v, domain_t d, uint8_t o)   { return dom_mask_##SHORT(v, d, o); }            \
    static TYPE      dom_unmask      (mskd_t* mv)                      { return dom_unmask_##SHORT(mv); }               \
    static void      dom_conv_btoa   (mskd_t* mv)                      { dom_conv_btoa_##SHORT(mv); }                   \
    static void      dom_conv_atob   (mskd_t* mv)                      { dom_conv_atob_##SHORT(mv); }                   \
};                                                                                                                      \

DEFINE_DOM_TRAITS(uint8_t, u8)
DEFINE_DOM_TRAITS(uint32_t, u32)
DEFINE_DOM_TRAITS(uint64_t, u64)

#undef DEFINE_DOM_TRAITS


TEMPLATE_TEST_CASE(
        "Assert DOM converter functions work correctly",
        "[unittest][dom]", uint8_t, uint32_t, uint64_t
) {
    const int order = GENERATE_COPY(range(1, 11));
    INFO("security order = " << order);

    TestType value[1];
    csprng_read_array(reinterpret_cast<uint8_t*>(value), sizeof(value));
    auto expected = static_cast<TestType>(value[0]);

    // Mask expected value with boolean domain
    auto* mv = dom_traits<TestType>::dom_mask(expected, DOMAIN_BOOLEAN, order);
    REQUIRE(mv->domain == DOMAIN_BOOLEAN);

    dom_traits<TestType>::dom_conv_btoa(mv);

    // Check unmasking from the arithmetic domain
    TestType unmasked_1 = dom_traits<TestType>::dom_unmask(mv);
    REQUIRE(unmasked_1 == expected);
    REQUIRE(mv->domain == DOMAIN_ARITHMETIC);

    dom_traits<TestType>::dom_conv_atob(mv);

    // Check unmasking back in the boolean domain
    TestType unmasked_2 = dom_traits<TestType>::dom_unmask(mv);
    REQUIRE(unmasked_2 == expected);
    REQUIRE(mv->domain == DOMAIN_BOOLEAN);

    dom_traits<TestType>::dom_free(mv);
}
