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
#include "clean_blake64.h"


TEST_CASE("permute64: zeros remain zeros", "[unittest][keygen]") {
    uint64_t m[16] = {0};
    permute64(m);
    for (const unsigned long long i : m) {
        REQUIRE(i == 0ULL);
    }
}


TEST_CASE("permute64: identity mapping yields expected schedule (cast to uint64_t)", "[unittest][keygen]") {
    uint64_t m[16];
    for (uint64_t i = 0; i < 16; ++i) {
        m[i] = i;
    }
    permute64(m);

    const uint64_t expected[16] = {
        2ULL, 6ULL, 3ULL, 10ULL, 7ULL,  0ULL,  4ULL, 13ULL,
        1ULL, 11ULL, 12ULL,  5ULL, 9ULL, 14ULL, 15ULL,  8ULL
    };
    for (int i = 0; i < 16; ++i) {
        REQUIRE(m[i] == expected[i]);
    }
}


TEST_CASE("g_mix64 produces expected state after successive calls", "[unittest][keygen]") {
    uint64_t state[16] = {};

    // After the first call: g_mix(0,4,8,12, 1,2)
    g_mix64(state, 0, 4, 8, 12, 1ULL, 2ULL);
    {
        const uint64_t expected1[16] = {
            0x0000000000000103ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
            0x0206000200020200ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
            0x0103000100010000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
            0x0103000000010000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL
        };
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state[i] == expected1[i]);
        }
    }

    // After the second call: g_mix(1,5,9,13, 1,2)
    g_mix64(state, 1, 5, 9, 13, 1ULL, 2ULL);
    {
        const uint64_t expected2[16] = {
            0x0000000000000103ULL, 0x0000000000000103ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
            0x0206000200020200ULL, 0x0206000200020200ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
            0x0103000100010000ULL, 0x0103000100010000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
            0x0103000000010000ULL, 0x0103000000010000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL
        };
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state[i] == expected2[i]);
        }
    }

    // After the third call: g_mix(2,6,10,14, 1,2)
    g_mix64(state, 2, 6, 10, 14, 1ULL, 2ULL);
    {
        const uint64_t expected3[16] = {
            0x0000000000000103ULL, 0x0000000000000103ULL, 0x0000000000000103ULL, 0x0000000000000000ULL,
            0x0206000200020200ULL, 0x0206000200020200ULL, 0x0206000200020200ULL, 0x0000000000000000ULL,
            0x0103000100010000ULL, 0x0103000100010000ULL, 0x0103000100010000ULL, 0x0000000000000000ULL,
            0x0103000000010000ULL, 0x0103000000010000ULL, 0x0103000000010000ULL, 0x0000000000000000ULL
        };
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state[i] == expected3[i]);
        }
    }

    // After the fourth call: g_mix(3,7,11,15, 1,2)
    g_mix64(state, 3, 7, 11, 15, 1ULL, 2ULL);
    {
        const uint64_t expected4[16] = {
            0x0000000000000103ULL, 0x0000000000000103ULL, 0x0000000000000103ULL, 0x0000000000000103ULL,
            0x0206000200020200ULL, 0x0206000200020200ULL, 0x0206000200020200ULL, 0x0206000200020200ULL,
            0x0103000100010000ULL, 0x0103000100010000ULL, 0x0103000100010000ULL, 0x0103000100010000ULL,
            0x0103000000010000ULL, 0x0103000000010000ULL, 0x0103000000010000ULL, 0x0103000000010000ULL
        };
        for (int i = 0; i < 16; ++i) {
            REQUIRE(state[i] == expected4[i]);
        }
    }
}


TEST_CASE("mix_into_state64 starting from zeros + m=0..15", "[unittest][keygen]") {
    uint64_t state[16] = {};

    uint64_t m[16];
    for (uint64_t i = 0; i < 16; ++i) {
        m[i] = i;
    }
    mix_into_state64(state, m);

    uint64_t expected[16] = {
        0x130E040401080D14ull, 0x191A081607122722ull, 0x1F260C18151C2930ull, 0x0D0200020B06232Eull,
        0x506E264202402412ull, 0x3C3E263206381422ull, 0x786E56521A702402ull, 0x748E46627E780402ull,
        0x294B2F3D2A2C1B0Full, 0x253713230A260F0Dull, 0x111B171902180313ull, 0x2D3F23270A320F09ull,
        0x272A191202190F01ull, 0x293C1F281C0D1B03ull, 0x232E0D0606190F0Dull, 0x0D10130C000D030Full
    };
    for (int i = 0; i < 16; ++i) {
        REQUIRE(state[i] == expected[i]);
    }
}


TEST_CASE("clean_compute_knc64: key=0xAA..AA, nonce=0xBB..BB → alternating 0xAAAAAAAABBBBBBBB/0xBBBBBBBBAAAAAAAA", "[unittest][keygen]") {
    uint64_t key[8];
    uint64_t nonce[8];
    uint64_t out[16];

    for (size_t i = 0; i < 8; ++i) {
        key[i] = 0xAAAAAAAAAAAAAAAAULL;
        nonce[i] = 0xBBBBBBBBBBBBBBBBULL;
    }
    clean_compute_knc64(key, nonce, out);

    for (size_t i = 0; i < 8; ++i) {
        REQUIRE(out[2*i]     == 0xAAAAAAAABBBBBBBBULL);
        REQUIRE(out[2*i + 1] == 0xBBBBBBBBAAAAAAAALL);
    }
}


TEST_CASE("clean_digest_context64 produces expected final state", "[unittest][keygen]") {
    constexpr uint64_t key[8] = {};
    uint64_t context[8] = {};
    uint64_t state[16] = {};

    clean_digest_context64(state, key, context);

    uint64_t expected[16] = {
        0xDC8B3C3143A0D4C1ULL, 0x580998D3DE81A26FULL, 0x0541A07C357EF61DULL, 0x0957A6015FDF7732ULL,
        0xA3356F649E3B2A21ULL, 0x4644C796512D7958ULL, 0xFDC0EACA13532EA9ULL, 0xDAFF756C91DDC1C0ULL,
        0xB8E4466483DAF7A4ULL, 0x9A0A4B07A037C39DULL, 0xE96BF8EBE8E826F2ULL, 0x24B439AE3061969DULL,
        0xAD5F490B09C82887ULL, 0x4297FEE81F33CBD3ULL, 0x9708FD326FEDDF3DULL, 0xFF42A3DAE1E43D7CULL,
    };
    for (int i = 0; i < 16; i++) {
        REQUIRE(state[i] == expected[i]);
    }
}
