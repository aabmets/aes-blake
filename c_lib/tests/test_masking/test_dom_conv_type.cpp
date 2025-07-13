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
#include <array>
#include <cinttypes>


template<typename L, typename S>
struct dom_traits;

#define DEFINE_DOM_TRAITS(L_TYPE, L_SHORT, S_TYPE, S_SHORT)                                                                 \
template<>                                                                                                                  \
struct dom_traits<L_TYPE, S_TYPE> {                                                                                         \
    using large_mskd_t  = masked_##L_TYPE;                                                                                  \
    using small_mskd_t  = masked_##S_TYPE;                                                                                  \
                                                                                                                            \
    static small_mskd_t*    mask_small        (S_TYPE v, domain_t d, uint8_t o)   { return dom_mask_##S_SHORT(v, d, o); }   \
    static S_TYPE           unmask_small      (small_mskd_t* mv)                  { return dom_unmask_##S_SHORT(mv); }      \
    static L_TYPE           unmask_large      (large_mskd_t* mv)                  { return dom_unmask_##L_SHORT(mv); }      \
    static void             free_small        (small_mskd_t* mv)                  { dom_free_##S_SHORT(mv); }               \
    static void             free_small_many   (small_mskd_t** mvs, uint8_t c)     { dom_free_many_##S_SHORT(mvs, c, 0); }   \
    static void             free_large        (large_mskd_t* mv)                  { dom_free_##L_SHORT(mv); }               \
                                                                                                                            \
    static large_mskd_t*    to_large          (small_mskd_t** parts)                                                        \
                                              { return dom_conv_##S_SHORT##_to_##L_SHORT(parts); }                          \
                                                                                                                            \
    static small_mskd_t**   to_small          (large_mskd_t* mv)                                                            \
                                              { return dom_conv_##L_SHORT##_to_##S_SHORT(mv); }                             \
};                                                                                                                          \

// 2-to-1 ratio
DEFINE_DOM_TRAITS(uint64_t, u64, uint32_t, u32)
DEFINE_DOM_TRAITS(uint32_t, u32, uint16_t, u16)
DEFINE_DOM_TRAITS(uint16_t, u16, uint8_t,  u8)

// 4-to-1 ratio
DEFINE_DOM_TRAITS(uint64_t, u64, uint16_t, u16)
DEFINE_DOM_TRAITS(uint32_t, u32, uint8_t,  u8)

// 8-to-1 ratio
DEFINE_DOM_TRAITS(uint64_t, u64, uint8_t,  u8)

#undef DEFINE_DOM_TRAITS


template<typename L, typename S>
static void roundtrip(uint8_t order)
{
    using traits = dom_traits<L, S>;
    constexpr size_t PARTS = sizeof(L) / sizeof(S);

    L original;
    csprng_read_array(reinterpret_cast<uint8_t*>(&original), sizeof(original));

    constexpr unsigned DIST_BITS = sizeof(S) * 8u;
    std::array<S, PARTS> chunks{};
    for (size_t i = 0; i < PARTS; ++i)
        chunks[i] = static_cast<S>(original >> (i * DIST_BITS));

    std::array<typename traits::small_mskd_t*, PARTS> parts{};
    for (size_t i = 0; i < PARTS; ++i) {
        parts[i] = traits::mask_small(chunks[i], DOMAIN_BOOLEAN, order);
        REQUIRE(parts[i] != nullptr);
    }

    auto* mv_large = traits::to_large(parts.data());
    REQUIRE(mv_large != nullptr);

    CHECK(traits::unmask_large(mv_large) == original);

    auto** back = traits::to_small(mv_large);
    REQUIRE(back != nullptr);
    for (size_t i = 0; i < PARTS; ++i) {
        REQUIRE(back[i] != nullptr);
        CHECK(traits::unmask_small(back[i]) == chunks[i]);
    }

    for (auto* mv : parts)
        traits::free_small(mv);
    traits::free_large(mv_large);
    traits::free_small_many(back, static_cast<uint8_t>(PARTS));
}


TEST_CASE("DOM type‑converter round‑trip across ratios 2,4,8", "[unittest][dom]")
{
    const int order = GENERATE_COPY(range(1, 4));
    INFO("security order = " << order);

    // 2-to-1 ratio
    roundtrip<uint64_t, uint32_t>(static_cast<uint8_t>(order));
    roundtrip<uint32_t, uint16_t>(static_cast<uint8_t>(order));
    roundtrip<uint16_t, uint8_t >(static_cast<uint8_t>(order));

    // 4-to-1 ratio
    roundtrip<uint64_t, uint16_t>(static_cast<uint8_t>(order));
    roundtrip<uint32_t, uint8_t >(static_cast<uint8_t>(order));

    // 8-to-1 ratio
    roundtrip<uint64_t, uint8_t >(static_cast<uint8_t>(order));
}
