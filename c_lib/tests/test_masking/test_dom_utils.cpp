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
#include <climits>
#include <cstring>
#include <vector>
#include "csprng.h"
#include "masking.h"


// -----------------------------------------------------------------------------
//  Type‑specific traits that map every dom_utils symbol to a single interface
// -----------------------------------------------------------------------------
template<typename T>
struct dom_traits;

#define DEFINE_DOM_TRAITS(TYPE, SHORT)                                                                                  \
template<>                                                                                                              \
struct dom_traits<TYPE> {                                                                                               \
    using mskd_t = masked_##TYPE;                                                                                       \
                                                                                                                        \
    /* Single-instance helpers */                                                                                       \
    static void      dom_free      (mskd_t *mv)                      { dom_free_##SHORT(mv); }                          \
    static void      dom_clear     (mskd_t *mv)                      { dom_clear_##SHORT(mv); }                         \
    static mskd_t*   dom_alloc     (domain_t d, uint8_t o)           { return dom_alloc_##SHORT(d, o); }                \
    static mskd_t*   dom_mask      (TYPE v, domain_t d, uint8_t o)   { return dom_mask_##SHORT(v, d, o); }              \
    static TYPE      dom_unmask    (mskd_t *mv)                      { return dom_unmask_##SHORT(mv); }                 \
    static void      dom_refresh   (mskd_t *mv)                      { dom_refresh_##SHORT(mv); }                       \
    static mskd_t*   dom_clone     (mskd_t *mv, bool z)              { return dom_clone_##SHORT(mv, z); }               \
                                                                                                                        \
    /* Array helpers */                                                                                                 \
    static void       dom_free_many      (mskd_t **mvs, uint8_t count, uint32_t skip_mask)                              \
                                         { dom_free_many_##SHORT(mvs, count, skip_mask); }                              \
                                                                                                                        \
    static void       dom_clear_many     (mskd_t **mvs, uint8_t count, uint32_t skip_mask)                              \
                                         { dom_clear_many_##SHORT(mvs, count, skip_mask); }                             \
                                                                                                                        \
    static mskd_t**   dom_alloc_many     (domain_t domain, uint8_t order, uint8_t count)                                \
                                         { return dom_alloc_many_##SHORT(domain, order, count); }                       \
                                                                                                                        \
    static mskd_t**   dom_mask_many      (const TYPE *values, domain_t doman, uint8_t order, uint32_t count)            \
                                         { return dom_mask_many_##SHORT(values, doman, order, count); }                 \
                                                                                                                        \
    static void       dom_unmask_many    (mskd_t **mvs, TYPE *out, uint8_t count)                                       \
                                         { dom_unmask_many_##SHORT(mvs, out, count); }                                  \
                                                                                                                        \
    static void       dom_refresh_many   (mskd_t **mvs, uint8_t count)                                                  \
                                         { dom_refresh_many_##SHORT(mvs, count); }                                      \
                                                                                                                        \
    static mskd_t**   dom_clone_many     (mskd_t *mv, bool zero_shares, uint8_t count)                                  \
                                         { return dom_clone_many_##SHORT(mv, zero_shares, count); }                     \
};                                                                                                                      \

DEFINE_DOM_TRAITS(uint8_t, u8)
DEFINE_DOM_TRAITS(uint16_t, u16)
DEFINE_DOM_TRAITS(uint32_t, u32)
DEFINE_DOM_TRAITS(uint64_t, u64)

#undef DEFINE_DOM_TRAITS


// -----------------------------------------------------------------------------
//  Helper type to iterate over the 6 (type, domain) combinations
// -----------------------------------------------------------------------------
template<typename T, domain_t Domain>
struct TypeDomainPair {
    using type = T;
    static constexpr domain_t domain = Domain;
};


// -----------------------------------------------------------------------------
//  Comprehensive test‑suite that exercises *all* public utilities
// -----------------------------------------------------------------------------
TEMPLATE_TEST_CASE(
        "DOM utility functions - full coverage", "[unittest][dom]",
        (TypeDomainPair<uint8_t, DOMAIN_BOOLEAN>),
        (TypeDomainPair<uint8_t, DOMAIN_ARITHMETIC>),
        (TypeDomainPair<uint16_t, DOMAIN_BOOLEAN>),
        (TypeDomainPair<uint16_t, DOMAIN_ARITHMETIC>),
        (TypeDomainPair<uint32_t, DOMAIN_BOOLEAN>),
        (TypeDomainPair<uint32_t, DOMAIN_ARITHMETIC>),
        (TypeDomainPair<uint64_t, DOMAIN_BOOLEAN>),
        (TypeDomainPair<uint64_t, DOMAIN_ARITHMETIC>)
) {
    using DataType = typename TestType::type;
    using MaskedType = typename dom_traits<DataType>::mskd_t;
    constexpr domain_t domain = TestType::domain;

    const uint8_t order = GENERATE_COPY(range(1, 4));
    INFO("security order = " << order);

    // ---------------------------------------------------------------------
    SECTION("Single allocation initialises all meta‑data and zeroes shares")
    {
        MaskedType* mv = dom_traits<DataType>::dom_alloc(domain, order);
        REQUIRE(mv != nullptr);
        REQUIRE(mv->domain == domain);
        REQUIRE(mv->order == order);
        REQUIRE(mv->share_count == order + 1);
        REQUIRE(mv->bit_length == sizeof(DataType) * CHAR_BIT);

        auto* shares = reinterpret_cast<DataType*>(mv->shares);
        for (uint8_t i = 0; i < mv->share_count; ++i)
            REQUIRE(shares[i] == static_cast<DataType>(0));

        dom_traits<DataType>::dom_free(mv);
    }

    // ---------------------------------------------------------------------
    SECTION("Bulk allocation produces *count* valid, independent objects")
    {
        constexpr uint8_t count = 4;
        MaskedType** mvs = dom_traits<DataType>::dom_alloc_many(domain, order, count);
        REQUIRE(mvs != nullptr);
        for (uint8_t i = 0; i < count; ++i) {
            REQUIRE(mvs[i] != nullptr);
            REQUIRE(mvs[i]->domain == domain);
            REQUIRE(mvs[i]->order == order);
        }
        dom_traits<DataType>::dom_free_many(mvs, count, 0u);
    }

    // ---------------------------------------------------------------------
    SECTION("Mask / unmask round‑trip retains original value")
    {
        DataType value;
        csprng_read_array(reinterpret_cast<uint8_t*>(&value), sizeof(value));

        MaskedType* mv = dom_traits<DataType>::dom_mask(value, domain, order);
        REQUIRE(dom_traits<DataType>::dom_unmask(mv) == value);

        dom_traits<DataType>::dom_free(mv);
    }

    // ---------------------------------------------------------------------
    SECTION("mask_many & unmask_many handle arrays consistently")
    {
        constexpr uint8_t count = 5;
        std::vector<DataType> values(count);
        csprng_read_array(reinterpret_cast<uint8_t*>(values.data()), count * sizeof(DataType));

        MaskedType** mvs = dom_traits<DataType>::dom_mask_many(values.data(), domain, order, count);
        REQUIRE(mvs != nullptr);

        std::vector<DataType> out(count, {});
        dom_traits<DataType>::dom_unmask_many(mvs, out.data(), count);
        REQUIRE(out == values);

        dom_traits<DataType>::dom_free_many(mvs, count, 0u);
    }

    // ---------------------------------------------------------------------
    SECTION("clear zeroes all shares while keeping meta‑data intact")
    {
        DataType value{};
        csprng_read_array(reinterpret_cast<uint8_t*>(&value), sizeof(value));

        MaskedType* mv = dom_traits<DataType>::dom_mask(value, domain, order);
        dom_traits<DataType>::dom_clear(mv);

        auto* shares = reinterpret_cast<DataType*>(mv->shares);
        for (uint8_t i = 0; i < mv->share_count; ++i)
            REQUIRE(shares[i] == static_cast<DataType>(0));

        dom_traits<DataType>::dom_free(mv);
    }

    // ---------------------------------------------------------------------
    SECTION("clear_many honours skip‑mask semantics")
    {
        constexpr uint8_t count = 3;
        std::vector<DataType> vals(count);
        csprng_read_array(reinterpret_cast<uint8_t*>(vals.data()), count * sizeof(DataType));

        MaskedType** mvs = dom_traits<DataType>::dom_mask_many(vals.data(), domain, order, count);
        REQUIRE(mvs != nullptr);

        // Skip index 0 -> binary 001
        constexpr uint32_t skip = 0b001u;
        dom_traits<DataType>::dom_clear_many(mvs, count, skip);

        // index 0 untouched
        REQUIRE(dom_traits<DataType>::dom_unmask(mvs[0]) == vals[0]);
        // indices 1 & 2 cleared
        for (uint8_t idx = 1; idx < count; ++idx) {
            auto* shares = reinterpret_cast<DataType*>(mvs[idx]->shares);
            for (uint8_t i = 0; i < mvs[idx]->share_count; ++i)
                REQUIRE(shares[i] == static_cast<DataType>(0));
        }

        dom_traits<DataType>::dom_free_many(mvs, count, 0u);
    }

    // ---------------------------------------------------------------------
    SECTION("refresh keeps logical value but changes at least one share")
    {
        DataType value{};
        csprng_read_array(reinterpret_cast<uint8_t*>(&value), sizeof(value));
        MaskedType* mv = dom_traits<DataType>::dom_mask(value, domain, order);

        // Snapshot previous shares
        std::vector<DataType> before(mv->share_count);
        std::memcpy(before.data(), mv->shares, mv->share_bytes);

        dom_traits<DataType>::dom_refresh(mv);
        REQUIRE(dom_traits<DataType>::dom_unmask(mv) == value);

        bool changed = false;
        const auto* after = reinterpret_cast<const DataType*>(mv->shares);
        for (uint8_t i = 0; i < mv->share_count; ++i)
            changed |= (after[i] != before[i]);
        REQUIRE(changed);  // at least one share altered

        dom_traits<DataType>::dom_free(mv);
    }

    // ---------------------------------------------------------------------
    SECTION("refresh_many updates every member in array")
    {
        constexpr uint8_t count = 3;
        std::vector<DataType> vals(count);
        csprng_read_array(reinterpret_cast<uint8_t*>(vals.data()), count * sizeof(DataType));

        MaskedType** mvs = dom_traits<DataType>::dom_mask_many(vals.data(), domain, order, count);
        REQUIRE(mvs != nullptr);

        // Preserve old shares for later comparison
        std::vector<std::vector<DataType>> snapshots(count);
        for (uint8_t i = 0; i < count; ++i) {
            snapshots[i].resize(mvs[i]->share_count);
            std::memcpy(snapshots[i].data(), mvs[i]->shares, mvs[i]->share_bytes);
        }

        dom_traits<DataType>::dom_refresh_many(mvs, count);

        for (uint8_t i = 0; i < count; ++i) {
            REQUIRE(dom_traits<DataType>::dom_unmask(mvs[i]) == vals[i]);
            bool changed = false;
            const auto* after = reinterpret_cast<const DataType*>(mvs[i]->shares);
            for (uint8_t j = 0; j < mvs[i]->share_count; ++j)
                changed |= (after[j] != snapshots[i][j]);
            REQUIRE(changed);  // at least one share altered
        }

        dom_traits<DataType>::dom_free_many(mvs, count, 0u);
    }

    // ---------------------------------------------------------------------
    SECTION("clone performs a deep copy with and without zero_shares")
    {
        DataType value{};
        csprng_read_array(reinterpret_cast<uint8_t*>(&value), sizeof(value));

        MaskedType *orig        = dom_traits<DataType>::dom_mask(value, domain, order);
        MaskedType *clone_full  = dom_traits<DataType>::dom_clone(orig, false);
        MaskedType *clone_zero  = dom_traits<DataType>::dom_clone(orig, true);

        // ---- zero_shares == false ----
        REQUIRE(clone_full != nullptr);
        REQUIRE(clone_full != orig);  // different memory
        REQUIRE(std::memcmp(clone_full, orig, orig->total_bytes) == 0); // identical content

        // Mutate clone, orig must stay intact
        auto* c_shares = reinterpret_cast<DataType*>(clone_full->shares);
        c_shares[0] ^= static_cast<DataType>(1);
        REQUIRE(dom_traits<DataType>::dom_unmask(orig) == value);

        // ---- zero_shares == true ----
        REQUIRE(clone_zero != nullptr);
        REQUIRE(clone_zero != orig);
        REQUIRE(clone_zero->order == orig->order);
        auto* z_shares = reinterpret_cast<DataType*>(clone_zero->shares);
        for (uint8_t i = 0; i < clone_zero->share_count; ++i)
            REQUIRE(z_shares[i] == static_cast<DataType>(0));

        dom_traits<DataType>::dom_free(clone_full);
        dom_traits<DataType>::dom_free(clone_zero);
        dom_traits<DataType>::dom_free(orig);
    }

    // ---------------------------------------------------------------------
    SECTION("clone_many replicates semantics across array")
    {
        DataType value{};
        csprng_read_array(reinterpret_cast<uint8_t*>(&value), sizeof(value));
        MaskedType* orig = dom_traits<DataType>::dom_mask(value, domain, order);
        constexpr uint8_t count = 4;

        // ---- zero_shares == false ----
        MaskedType** full_clones = dom_traits<DataType>::dom_clone_many(orig, false, count);
        REQUIRE(full_clones != nullptr);
        for (uint8_t i = 0; i < count; ++i) {
            REQUIRE(full_clones[i] != nullptr);
            REQUIRE(full_clones[i] != orig);
            for (uint8_t j = i + 1; j < count; ++j)
                REQUIRE(full_clones[i] != full_clones[j]);
            REQUIRE(std::memcmp(full_clones[i], orig, orig->total_bytes) == 0);
        }

        // mutate one clone to ensure independence
        auto* shares0 = reinterpret_cast<DataType*>(full_clones[0]->shares);
        shares0[0] ^= static_cast<DataType>(1);
        REQUIRE(dom_traits<DataType>::dom_unmask(orig) == value);
        for (uint8_t i = 1; i < count; ++i)
            REQUIRE(std::memcmp(full_clones[i], orig, orig->total_bytes) == 0);

        // ---- zero_shares == true ----
        MaskedType** zero_clones = dom_traits<DataType>::dom_clone_many(orig, true, count);
        REQUIRE(zero_clones != nullptr);
        for (uint8_t i = 0; i < count; ++i) {
            REQUIRE(zero_clones[i] != nullptr);
            auto* shares = reinterpret_cast<DataType*>(zero_clones[i]->shares);
            for (uint8_t s = 0; s < zero_clones[i]->share_count; ++s)
                REQUIRE(shares[s] == static_cast<DataType>(0));
        }

        dom_traits<DataType>::dom_free_many(full_clones, count, 0u);
        dom_traits<DataType>::dom_free_many(zero_clones, count, 0u);
        dom_traits<DataType>::dom_free(orig);
    }

    // ---------------------------------------------------------------------
    SECTION("free_many honours skip‑mask by leaving chosen items alive")
    {
        constexpr uint8_t count = 3;
        MaskedType** mvs = dom_traits<DataType>::dom_alloc_many(domain, order, count);
        REQUIRE(mvs != nullptr);

        MaskedType* kept = mvs[1];  // keep index 1 alive
        constexpr uint32_t skip_mask = 0b010u;  // binary: keep index‑1
        dom_traits<DataType>::dom_free_many(mvs, count, skip_mask);

        // array memory was released, but kept pointer must still be valid
        REQUIRE(kept->order == order);
        dom_traits<DataType>::dom_free(kept);
    }
}
