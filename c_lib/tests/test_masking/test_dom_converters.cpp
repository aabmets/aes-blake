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
    static void       dom_free        (mskd_t *mv)                            { dom_free_##SHORT(mv); }                 \
    static mskd_t*    dom_mask        (TYPE v, domain_t d, uint8_t o)         { return dom_mask_##SHORT(v, d, o); }     \
    static TYPE       dom_unmask      (mskd_t* mv)                            { return dom_unmask_##SHORT(mv); }        \
    static int        dom_conv_btoa   (mskd_t* mv)                            { return dom_conv_btoa_##SHORT(mv); }     \
    static int        dom_conv_atob   (mskd_t* mv)                            { return dom_conv_atob_##SHORT(mv); }     \
                                                                                                                        \
    static int        dom_conv_many   (mskd_t** mv, uint8_t c, domain_t td)                                             \
                                      { return dom_conv_many_##SHORT(mv, c, td); }                                      \
                                                                                                                        \
    static mskd_t**   dom_mask_many   (const TYPE *values, domain_t doman, uint8_t order, uint32_t count)               \
                                      { return dom_mask_many_##SHORT(values, doman, order, count); }                    \
                                                                                                                        \
    static void       dom_free_many   (mskd_t **mvs, uint8_t count, uint32_t skip_mask)                                 \
                                      { dom_free_many_##SHORT(mvs, count, skip_mask); }                                 \
};                                                                                                                      \

DEFINE_DOM_TRAITS(uint8_t, u8)
DEFINE_DOM_TRAITS(uint16_t, u16)
DEFINE_DOM_TRAITS(uint32_t, u32)
DEFINE_DOM_TRAITS(uint64_t, u64)

#undef DEFINE_DOM_TRAITS


TEMPLATE_TEST_CASE(
        "Assert DOM converter functions work correctly",
        "[unittest][dom]", uint8_t, uint16_t, uint32_t, uint64_t
) {
    const int order = GENERATE_COPY(range(1, 4));
    INFO("security order = " << order);

    TestType value[1];
    csprng_read_array(reinterpret_cast<uint8_t*>(value), sizeof(value));
    auto expected = static_cast<TestType>(value[0]);

    // Mask expected value with boolean domain
    auto* mv = dom_traits<TestType>::dom_mask(expected, DOMAIN_BOOLEAN, order);
    REQUIRE(mv->domain == DOMAIN_BOOLEAN);

    REQUIRE(dom_traits<TestType>::dom_conv_btoa(mv) == 0);

    // Check unmasking from the arithmetic domain
    TestType unmasked_1 = dom_traits<TestType>::dom_unmask(mv);
    REQUIRE(unmasked_1 == expected);
    REQUIRE(mv->domain == DOMAIN_ARITHMETIC);

    REQUIRE(dom_traits<TestType>::dom_conv_atob(mv) == 0);

    // Check unmasking back in the boolean domain
    TestType unmasked_2 = dom_traits<TestType>::dom_unmask(mv);
    REQUIRE(unmasked_2 == expected);
    REQUIRE(mv->domain == DOMAIN_BOOLEAN);

    dom_traits<TestType>::dom_free(mv);
}


TEMPLATE_TEST_CASE(
        "dom_conv_many preserves values across domains",
        "[unittest][dom]", uint8_t, uint16_t, uint32_t, uint64_t
) {
    constexpr uint8_t COUNT = 6;
    const int order = GENERATE_COPY(range(1, 4));
    INFO("security order = " << order);

    TestType texts[COUNT];
    csprng_read_array(reinterpret_cast<uint8_t*>(texts), sizeof(texts));

    auto** mvs = dom_traits<TestType>::dom_mask_many
        (texts, DOMAIN_BOOLEAN, static_cast<uint8_t>(order), COUNT);

    REQUIRE(mvs != nullptr);
    for (uint8_t i = 0; i < COUNT; ++i)
        REQUIRE(mvs[i]->domain == DOMAIN_BOOLEAN);

    REQUIRE(dom_traits<TestType>::dom_conv_many(mvs, COUNT, DOMAIN_ARITHMETIC) == 0);
    for (uint8_t i = 0; i < COUNT; ++i) {
        REQUIRE(mvs[i]->domain == DOMAIN_ARITHMETIC);
        CHECK(dom_traits<TestType>::dom_unmask(mvs[i]) == texts[i]);
    }

    REQUIRE(dom_traits<TestType>::dom_conv_many(mvs, COUNT, DOMAIN_BOOLEAN) == 0);
    for (uint8_t i = 0; i < COUNT; ++i) {
        REQUIRE(mvs[i]->domain == DOMAIN_BOOLEAN);
        CHECK(dom_traits<TestType>::dom_unmask(mvs[i]) == texts[i]);
    }

    dom_traits<TestType>::dom_free_many(mvs, COUNT, 0);
}
