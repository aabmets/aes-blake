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

#define DEFINE_DOM_TRAITS(TYPE, SHORT_TYPE)                                                 \
template<>                                                                                  \
struct dom_traits<TYPE> {                                                                   \
    using mskd_t = masked_##TYPE;                                                           \
    static mskd_t* dom_alloc(const uint8_t share_count)                                     \
        { return dom_alloc_##SHORT_TYPE(share_count); }                                     \
    static void dom_free(mskd_t* mv)                                                        \
        { dom_free_##SHORT_TYPE(mv); }                                                      \
    static mskd_t* dom_mask(const TYPE value, const domain_t domain, const uint8_t order)   \
        { return dom_mask_##SHORT_TYPE(value, domain, order); }                             \
    static TYPE dom_unmask(mskd_t* mv)                                                      \
        { return dom_unmask_##SHORT_TYPE(mv); }                                             \
    static mskd_t* dom_clone(mskd_t* mv)                                                    \
        { return dom_clone_##SHORT_TYPE(mv); }                                              \
    static void dom_refresh_mask(mskd_t* mv)                                                \
        { dom_refresh_mask_##SHORT_TYPE(mv); }                                              \
};                                                                                          \

DEFINE_DOM_TRAITS(uint8_t, u8)
DEFINE_DOM_TRAITS(uint32_t, u32)
DEFINE_DOM_TRAITS(uint64_t, u64)

#undef DEFINE_DOM_TRAITS


// Helper to create type-domain pairs
template<typename T, domain_t Domain>
struct TypeDomainPair {
    using type = T;
    static constexpr domain_t domain = Domain;
};


TEMPLATE_TEST_CASE(
        "Assert DOM utility functions work correctly", "[unittest][dom]",
        (TypeDomainPair<uint8_t, DOMAIN_BOOLEAN>),
        (TypeDomainPair<uint8_t, DOMAIN_ARITHMETIC>),
        (TypeDomainPair<uint32_t, DOMAIN_BOOLEAN>),
        (TypeDomainPair<uint32_t, DOMAIN_ARITHMETIC>),
        (TypeDomainPair<uint64_t, DOMAIN_BOOLEAN>),
        (TypeDomainPair<uint64_t, DOMAIN_ARITHMETIC>)
) {
    using DataType = typename TestType::type;
    constexpr domain_t domain = TestType::domain;
    const int order = GENERATE_COPY(range(1, 11));
    INFO("security order = " << order);

    DataType expected[1];
    csprng_read_array((uint8_t*)expected, sizeof(expected));

    // Mask expected value and its inverse
    auto* mv_1 = dom_traits<DataType>::dom_mask(expected[0], domain, order);
    auto* mv_2 = dom_traits<DataType>::dom_mask(~expected[0], domain, order);

    // Verify initial values
    DataType manually_unmasked_1 = mv_1->shares[0];
    DataType manually_unmasked_2 = mv_2->shares[0];
    auto pairs = std::array{
        std::make_pair(mv_1, &manually_unmasked_1),
        std::make_pair(mv_2, &manually_unmasked_2)
    };

    // Iterate and manually unmask based on the domain
    for (auto& [mv, result_ptr] : pairs) {
        if constexpr (domain == DOMAIN_BOOLEAN) {
            for (int i = 1; i <= order; ++i) {
                *result_ptr ^= mv->shares[i];
            }
        } else {
            for (int i = 1; i <= order; ++i) {
                *result_ptr += mv->shares[i];
            }
        }
    }

    DataType expected_1 = static_cast<DataType>(expected[0]);
    DataType expected_2 = static_cast<DataType>(~expected[0]);

    REQUIRE(manually_unmasked_1 == expected_1);
    REQUIRE(manually_unmasked_2 == expected_2);

    auto* clone = dom_traits<DataType>::dom_clone(mv_1);
    dom_traits<DataType>::dom_refresh_mask(mv_2);

    DataType func_unmasked_1 = dom_traits<DataType>::dom_unmask(clone);
    DataType func_unmasked_2 = dom_traits<DataType>::dom_unmask(mv_2);

    REQUIRE(func_unmasked_1 == expected_1);
    REQUIRE(func_unmasked_2 == expected_2);

    dom_traits<DataType>::dom_free(clone);
    dom_traits<DataType>::dom_free(mv_1);
    dom_traits<DataType>::dom_free(mv_2);
}
