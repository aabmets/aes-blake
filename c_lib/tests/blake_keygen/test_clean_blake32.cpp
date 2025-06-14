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


TEST_CASE("clean_compute_knc32: key=0xAA..AA, nonce=0xBB..BB → alternating 0xAAAABBBB/0xBBBBAAAA", "[unittest][keygen]") {
    uint32_t key[8];
    uint32_t nonce[8];
    uint32_t out[16];

    for (size_t i = 0; i < 8; ++i) {
        key[i] = 0xAAAAAAAAu;
        nonce[i] = 0xBBBBBBBBu;
    }
    clean_compute_knc32(key, nonce, out);

    for (size_t i = 0; i < 8; ++i) {
        REQUIRE(out[2*i]     == 0xAAAABBBBu);
        REQUIRE(out[2*i + 1] == 0xBBBBAAAAu);
    }
}


TEST_CASE("clean_digest_context32 produces expected final state", "[unittest][keygen]") {
    constexpr uint32_t key[8] = {};
    uint32_t context[8] = {};
    uint32_t state[16] = {};

    clean_digest_context32(state, key, context);

    uint32_t expected[16] = {
        0xC2EB894Fu, 0x3B147EEAu, 0xAE5A1CB8u, 0x904DF606u,
        0xC5393EF8u, 0x07D4024Eu, 0x842E23EEu, 0x3873ACB2u,
        0xA8E23005u, 0xDE6C2E0Bu, 0x3AB21C1Bu, 0x246BA208u,
        0xBD35DCD2u, 0x4969FFC6u, 0xE03984FAu, 0xE4133986u,
    };
    for (int i = 0; i < 16; i++) {
        REQUIRE(state[i] == expected[i]);
    }
}
