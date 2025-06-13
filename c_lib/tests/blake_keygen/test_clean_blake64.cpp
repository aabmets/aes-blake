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


TEST_CASE("sub_bytes64: ENC maps all-zero words → 0x6363636363636363", "[unittest][keygen]") {
    uint64_t state[16] = {0};

    sub_bytes64(state);

    for (const unsigned long long i : state) {
        REQUIRE(i == 0x6363636363636363ULL);
    }
}


TEST_CASE("compute_key_nonce_composite64: key=0xAA..AA, nonce=0xBB..BB → alternating 0xAAAAAAAABBBBBBBB/0xBBBBBBBBAAAAAAAA", "[unittest][keygen]") {
    uint64_t key[8];
    uint64_t nonce[8];
    uint64_t out[16];

    for (size_t i = 0; i < 8; ++i) {
        key[i] = 0xAAAAAAAAAAAAAAAAULL;
        nonce[i] = 0xBBBBBBBBBBBBBBBBULL;
    }
    compute_key_nonce_composite64(key, nonce, out);

    for (size_t i = 0; i < 8; ++i) {
        REQUIRE(out[2*i]     == 0xAAAAAAAABBBBBBBBULL);
        REQUIRE(out[2*i + 1] == 0xBBBBBBBBAAAAAAAALL);
    }
}


TEST_CASE("digest_context64 produces expected final state", "[unittest][keygen]") {
    constexpr uint64_t key[8] = {};
    uint64_t context[8] = {};
    uint64_t state[16] = {};

    digest_context64(state, key, context);

    uint64_t expected[16] = {
        0x863DEBC71AE04878ULL, 0x6A0146661D0C3AA8ULL,
        0x6B83E01096F342A4ULL, 0x015B247CCF9EF523ULL,
        0x0A96A8430BE2E5FDULL, 0x5A1BC690D1D8B66AULL,
        0x54BA87747DED31D3ULL, 0x57169D5081C178BAULL,
        0x6C695A43EC576849ULL, 0xB867B3C5E09A2E5EULL,
        0x1E7F41E99B9BF789ULL, 0x368D12E404EF905EULL,
        0x95CF3B2B01E83417ULL, 0x2C88BB9BC0C31F66ULL,
        0x88305423A8559E27ULL, 0x162C0A57F8692710ULL
    };
    for (int i = 0; i < 16; i++) {
        REQUIRE(state[i] == expected[i]);
    }
}
