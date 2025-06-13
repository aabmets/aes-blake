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
#include "clean_blake32.h"
#include "aes_sbox.h"


TEST_CASE("permute32: zeros remain zeros", "[unittest][keygen]") {
    uint32_t m[16] = {0};
    permute32(m);
    for (const unsigned int i : m) {
        REQUIRE(i == 0u);
    }
}


TEST_CASE("permute32: identity mapping yields expected schedule", "[unittest][keygen]") {
    uint32_t m[16];
    for (uint32_t i = 0; i < 16; ++i) {
        m[i] = i;
    }
    permute32(m);

    const uint32_t expected[16] = {
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
    };
    for (int i = 0; i < 16; ++i) {
        REQUIRE(m[i] == expected[i]);
    }
}


TEST_CASE("g_mix32 produces expected state after successive calls", "[unittest][keygen]") {
    uint32_t state[16] = {};

    // After the first call: g_mix(0,4,8,12, 1,2)
    g_mix32(state, 0, 4, 8, 12, 1u, 2u);
    {
        const uint32_t expected1[16] = {
            0x00000013u, 0x00000000u, 0x00000000u, 0x00000000u,
            0x20260202u, 0x00000000u, 0x00000000u, 0x00000000u,
            0x13010100u, 0x00000000u, 0x00000000u, 0x00000000u,
            0x13000100u, 0x00000000u, 0x00000000u, 0x00000000u
        };
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state[i] == expected1[i]);
        }
    }

    // After the second call: g_mix(1,5,9,13, 1,2)
    g_mix32(state, 1, 5, 9, 13, 1u, 2u);
    {
        const uint32_t expected2[16] = {
            0x00000013u, 0x00000013u, 0x00000000u, 0x00000000u,
            0x20260202u, 0x20260202u, 0x00000000u, 0x00000000u,
            0x13010100u, 0x13010100u, 0x00000000u, 0x00000000u,
            0x13000100u, 0x13000100u, 0x00000000u, 0x00000000u
        };
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state[i] == expected2[i]);
        }
    }

    // After the third call: g_mix(2,6,10,14, 1,2)
    g_mix32(state, 2, 6, 10, 14, 1u, 2u);
    {
        const uint32_t expected3[16] = {
            0x00000013u, 0x00000013u, 0x00000013u, 0x00000000u,
            0x20260202u, 0x20260202u, 0x20260202u, 0x00000000u,
            0x13010100u, 0x13010100u, 0x13010100u, 0x00000000u,
            0x13000100u, 0x13000100u, 0x13000100u, 0x00000000u
        };
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state[i] == expected3[i]);
        }
    }

    // After the fourth call: g_mix(3,7,11,15, 1,2)
    g_mix32(state, 3, 7, 11, 15, 1u, 2u);
    {
        const uint32_t expected4[16] = {
            0x00000013u, 0x00000013u, 0x00000013u, 0x00000013u,
            0x20260202u, 0x20260202u, 0x20260202u, 0x20260202u,
            0x13010100u, 0x13010100u, 0x13010100u, 0x13010100u,
            0x13000100u, 0x13000100u, 0x13000100u, 0x13000100u
        };
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state[i] == expected4[i]);
        }
    }
}


TEST_CASE("mix_into_state32 starting from zeros + m=0..15", "[unittest][keygen]") {
    uint32_t state[16] = {};

    uint32_t m[16];
    for (uint32_t i = 0; i < 16; ++i) {
        m[i] = i;
    }
    mix_into_state32(state, m);

    uint32_t expected[16] = {
        0x952AB9C9u, 0x7A41633Au, 0x5E47082Cu, 0xB024987Eu,
        0x4E2C267Au, 0xDB3491DAu, 0x19C80149u, 0xF331BDEEu,
        0x05B20CC7u, 0xA631AAD3u, 0xCEA858DEu, 0x1DAFFE74u,
        0xA87276E2u, 0xF65026EDu, 0x7CB45FD1u, 0x83972794u
    };
    for (int i = 0; i < 16; ++i) {
        REQUIRE(state[i] == expected[i]);
    }
}


TEST_CASE("sub_bytes32: DEC (inverse) of 0x63636363 returns zero", "[unittest][keygen]") {
    uint32_t state[16] = {};

    sub_bytes32(state);

    for (const unsigned int i : state) {
        REQUIRE(i == 0x63636363U);
    }

    for (const unsigned int v : state) {
        const auto b0 = static_cast<uint8_t>(v >> 24 & 0xFF);
        const auto b1 = static_cast<uint8_t>(v >> 16 & 0xFF);
        const auto b2 = static_cast<uint8_t>(v >>  8 & 0xFF);
        const auto b3 = static_cast<uint8_t>(v       & 0xFF);

        const uint8_t ib0 = aes_inv_sbox[b0];
        const uint8_t ib1 = aes_inv_sbox[b1];
        const uint8_t ib2 = aes_inv_sbox[b2];
        const uint8_t ib3 = aes_inv_sbox[b3];

        const uint32_t original = static_cast<uint32_t>(ib0) << 24
                                | static_cast<uint32_t>(ib1) << 16
                                | static_cast<uint32_t>(ib2) <<  8
                                | static_cast<uint32_t>(ib3);

        REQUIRE(original == 0x00000000U);
    }
}


TEST_CASE("compute_key_nonce_composite32: key=0xAA..AA, nonce=0xBB..BB → alternating 0xAAAABBBB/0xBBBBAAAA", "[unittest][keygen]") {
    uint32_t key[8];
    uint32_t nonce[8];
    uint32_t out[16];

    for (size_t i = 0; i < 8; ++i) {
        key[i] = 0xAAAAAAAAu;
        nonce[i] = 0xBBBBBBBBu;
    }
    compute_key_nonce_composite32(key, nonce, out);

    for (size_t i = 0; i < 8; ++i) {
        REQUIRE(out[2*i]     == 0xAAAABBBBu);
        REQUIRE(out[2*i + 1] == 0xBBBBAAAAu);
    }
}


TEST_CASE("digest_context32 produces expected final state", "[unittest][keygen]") {
    constexpr uint32_t key[8] = {};
    uint32_t context[8] = {};
    uint32_t state[16] = {};

    digest_context32(state, key, context);

    uint32_t expected[16] = {
        0x25E9A784u, 0xE2FAF387u, 0xE4BE9C6Cu, 0x60E3426Fu,
        0xA612B241u, 0xC548772Fu, 0x5F312628u, 0x078F9137u,
        0xC298046Bu, 0x1D50312Bu, 0x80379CAFu, 0x367F3A30u,
        0x7A9686B5u, 0x3BF916B4u, 0xE1125F2Du, 0x697D1244u
    };
    for (int i = 0; i < 16; i++) {
        REQUIRE(state[i] == expected[i]);
    }
}


TEST_CASE("derive_keys32 matches Python test vectors", "[unittest][keygen]") {
    // 1) Prepare a zeroed key[8] and zeroed nonce/context[8].
    uint32_t zero_key[8]   = {};
    uint32_t zero_nonce[8] = {};

    // 2) Compute the initial state by “digesting the context” (all-zero key/nonce).
    uint32_t init_state[16] = {};
    digest_context32(init_state, zero_key, zero_nonce);

    // 3) Compute knc[16] via compute_key_nonce_composite32(zero_key, zero_nonce, knc).
    uint32_t knc[16];
    compute_key_nonce_composite32(zero_key, zero_nonce, knc);

    // 4) We will derive key_count=10 round‐keys for counters 0, 1, 2 and domains MSG, HDR, CHK.
    constexpr size_t key_count = 10;
    uint8_t out_keys1[key_count][16];
    uint8_t out_keys2[key_count][16];

    // 5) Expected first‐round outputs (Python pytest):
    struct Expected {
        KDFDomain domain;
        uint64_t  counter;
        uint8_t   expected_k1[16];
        uint8_t   expected_k2[16];
    };

    Expected cases[] = {
        {
            KDFDomain_MSG,
            0ULL,
            {  // expected_k1 for (domain=MSG, counter=0)
                0xB3, 0xA6, 0xCD, 0xB0,
                0x1A, 0x95, 0x57, 0x74,
                0x28, 0xE8, 0xE4, 0x87,
                0xE4, 0xEC, 0x45, 0x8E
            },
            {  // expected_k2 for (domain=MSG, counter=0)
                0xA1, 0xB9, 0x28, 0x0A,
                0x25, 0xD5, 0x62, 0xD9,
                0x7B, 0x2C, 0x69, 0x63,
                0x45, 0xDF, 0xEE, 0x7F
            }
        },
        {
            KDFDomain_HDR,
            1ULL,
            {  // expected_k1 for (domain=HDR, counter=1)
                0x39, 0xA3, 0x42, 0x5C,
                0x5C, 0x25, 0x67, 0x1D,
                0xF0, 0x09, 0x32, 0xA6,
                0xC7, 0x0F, 0xF7, 0xE4
            },
            {  // expected_k2 for (domain=HDR, counter=1)
                0xC7, 0x21, 0xD5, 0x05,
                0x34, 0xC2, 0x50, 0xD1,
                0xD8, 0x26, 0x2D, 0x2E,
                0x01, 0xB5, 0xA2, 0x11
            }
        },
        {
            KDFDomain_CHK,
            2ULL,
            {  // expected_k1 for (domain=CHK, counter=2)
                0x47, 0x64, 0xEA, 0xEA,
                0x04, 0x9D, 0x16, 0xCD,
                0x42, 0xE7, 0x39, 0x85,
                0x52, 0x46, 0xF8, 0xB5
            },
            {  // expected_k2 for (domain=CHK, counter=2)
                0x21, 0xE9, 0x52, 0xD6,
                0xF7, 0x9C, 0xE2, 0x12,
                0x62, 0x1A, 0x3D, 0x96,
                0xD6, 0x41, 0x84, 0x6E
            }
        }
    };

    for (const auto& [
            domain,
            counter,
            expected_k1,
            expected_k2
        ] : cases) {

        // 6) Call derive_keys32
        derive_keys32(
            init_state,
            knc,
            key_count,
            counter,
            domain,
            out_keys1,
            out_keys2
        );

        // 7) Verify that out_keys1[0] and out_keys2[0]
        //    match the expected arrays for this test case.
        for (int i = 0; i < 16; i++) {
            REQUIRE(out_keys1[0][i] == expected_k1[i]);
            REQUIRE(out_keys2[0][i] == expected_k2[i]);
        }
    }
}