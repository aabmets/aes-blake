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
    static void dom_copy(mskd_t* mv_src, mskd_t* mv_tgt)                        \
        { dom_copy_##SHORT_TYPE(mv_src, mv_tgt); }                              \
    static void dom_refresh_mask(mskd_t* mv)                                    \
        { dom_refresh_mask_##SHORT_TYPE(mv); }                                  \
};                                                                              \

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
        "2nd-order DOM utility functions work correctly", "[unittest][dom]",
        (TypeDomainPair<uint8_t, DOMAIN_BOOLEAN>),
        (TypeDomainPair<uint8_t, DOMAIN_ARITHMETIC>),
        (TypeDomainPair<uint32_t, DOMAIN_BOOLEAN>),
        (TypeDomainPair<uint32_t, DOMAIN_ARITHMETIC>),
        (TypeDomainPair<uint64_t, DOMAIN_BOOLEAN>),
        (TypeDomainPair<uint64_t, DOMAIN_ARITHMETIC>)
) {
    using DataType = typename TestType::type;
    constexpr domain_t domain = TestType::domain;

    for (int i = 0; i < 100; i++) {
        DataType expected[1];
        csprng_read_array((uint8_t*)(expected), sizeof(expected));

        // Mask expected value and its inverse
        auto* mv_src = dom_traits<DataType>::dom_mask(expected[0], domain);
        auto* mv_tgt = dom_traits<DataType>::dom_mask(~expected[0], domain);

        // Verify initial values
        DataType manually_unmasked_src, manually_unmasked_tgt;
        auto pairs = std::array{
            std::make_pair(mv_src, &manually_unmasked_src),
            std::make_pair(mv_tgt, &manually_unmasked_tgt)
        };

        // Iterate and manually unmask based on the domain
        for (auto& [mv, result_ptr] : pairs) {
            if constexpr (domain == DOMAIN_BOOLEAN) {
                *result_ptr = mv->shares[0] ^ mv->shares[1] ^ mv->shares[2];
            } else {
                *result_ptr = mv->shares[0] - mv->shares[1] - mv->shares[2];
            }
        }

        REQUIRE(manually_unmasked_src == static_cast<DataType>(expected[0]));
        REQUIRE(manually_unmasked_tgt == static_cast<DataType>(~expected[0]));
        REQUIRE(manually_unmasked_src != manually_unmasked_tgt);

        // Target should now be identical to Source
        dom_traits<DataType>::dom_copy(mv_src, mv_tgt);
        dom_traits<DataType>::dom_refresh_mask(mv_tgt);

        DataType func_unmasked_src = dom_traits<DataType>::dom_unmask(mv_src);
        DataType func_unmasked_tgt = dom_traits<DataType>::dom_unmask(mv_tgt);

        REQUIRE(func_unmasked_src == expected[0]);
        REQUIRE(func_unmasked_tgt == expected[0]);
    }
}
