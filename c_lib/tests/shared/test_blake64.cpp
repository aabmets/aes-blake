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
#include "blake64.h"
#include "aes_sbox.h"


TEST_CASE("rotr64: rotating by 0 returns the original value", "[rotr64]") {
    REQUIRE(rotr64(0x0000000000000000ULL, 0) == 0x0000000000000000ULL);
    REQUIRE(rotr64(0x0123456789ABCDEFULL, 0) == 0x0123456789ABCDEFULL);
}


TEST_CASE("rotr64: basic rotations", "[rotr64]") {
    SECTION("rotate a single bit from LSB to MSB") {
        uint64_t x = 0x0000000000000001ULL; // bit0 set
        REQUIRE(rotr64(x, 1) == 0x8000000000000000ULL);
        REQUIRE(rotr64(x, 2) == 0x4000000000000000ULL);
        REQUIRE(rotr64(x, 63) == 0x0000000000000002ULL);
    }

    SECTION("rotate an arbitrary pattern by 16") {
        uint64_t x = 0x1122334455667788ULL;
        // Expected: 0x7788112233445566
        REQUIRE(rotr64(x, 16) == 0x7788112233445566ULL);
    }

    SECTION("rotate a pattern by half the word size") {
        uint64_t x = 0xF0F0F0F0F0F0F0F0ULL;
        // Rotating by 32 should swap high and low 32-bit halves
        REQUIRE(rotr64(x, 32) == 0xF0F0F0F0F0F0F0F0ULL);
    }

    SECTION("rotate by various amounts on 0xAAAAAAAAAAAAAAAA") {
        uint64_t x = 0xAAAAAAAAAAAAAAAAULL; // alternating bits: 1010...
        REQUIRE(rotr64(x, 1)  == 0x5555555555555555ULL); // complement pattern
        REQUIRE(rotr64(x, 7)  == 0x5555555555555555ULL);
        REQUIRE(rotr64(x, 2)  == 0xAAAAAAAAAAAAAAAAULL); // same pattern
        REQUIRE(rotr64(x, 62) == 0xAAAAAAAAAAAAAAAAULL);
    }
}


TEST_CASE("permute64: zeros remain zeros", "[permute64]") {
    uint64_t m[16] = {0};
    permute64(m);
    for (const unsigned long long i : m) {
        REQUIRE(i == 0ULL);
    }
}


TEST_CASE("permute64: identity mapping yields expected schedule (cast to uint64_t)", "[permute64]") {
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


TEST_CASE("g_mix64 produces expected state after successive calls", "[g_mix64]") {
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


TEST_CASE("mix_into_state64 starting from zeros + m=0..15", "[blake64]") {
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


TEST_CASE("sub_bytes64: ENC maps all-zero words → 0x6363636363636363", "[sub_bytes64][ENC]") {
    uint64_t state[16] = {0};

    sub_bytes64(state);

    for (const unsigned long long i : state) {
        REQUIRE(i == 0x6363636363636363ULL);
    }
}


TEST_CASE("sub_bytes64: DEC (inverse) of 0x6363636363636363 returns zero", "[sub_bytes64][DEC]") {
    uint64_t state[16] = {0};

    sub_bytes64(state);

    for (const unsigned long long i : state) {
        REQUIRE(i == 0x6363636363636363ULL);
    }

    for (const unsigned long long v : state) {
        const auto b0 = static_cast<uint8_t>(v >> 56 & 0xFF);
        const auto b1 = static_cast<uint8_t>(v >> 48 & 0xFF);
        const auto b2 = static_cast<uint8_t>(v >> 40 & 0xFF);
        const auto b3 = static_cast<uint8_t>(v >> 32 & 0xFF);
        const auto b4 = static_cast<uint8_t>(v >> 24 & 0xFF);
        const auto b5 = static_cast<uint8_t>(v >> 16 & 0xFF);
        const auto b6 = static_cast<uint8_t>(v >>  8 & 0xFF);
        const auto b7 = static_cast<uint8_t>(v       & 0xFF);

        const uint8_t ib0 = aes_inv_sbox[b0];
        const uint8_t ib1 = aes_inv_sbox[b1];
        const uint8_t ib2 = aes_inv_sbox[b2];
        const uint8_t ib3 = aes_inv_sbox[b3];
        const uint8_t ib4 = aes_inv_sbox[b4];
        const uint8_t ib5 = aes_inv_sbox[b5];
        const uint8_t ib6 = aes_inv_sbox[b6];
        const uint8_t ib7 = aes_inv_sbox[b7];

        const uint64_t original = (static_cast<uint64_t>(ib0) << 56)
                                | (static_cast<uint64_t>(ib1) << 48)
                                | (static_cast<uint64_t>(ib2) << 40)
                                | (static_cast<uint64_t>(ib3) << 32)
                                | (static_cast<uint64_t>(ib4) << 24)
                                | (static_cast<uint64_t>(ib5) << 16)
                                | (static_cast<uint64_t>(ib6) <<  8)
                                |  static_cast<uint64_t>(ib7);

        REQUIRE(original == 0x0000000000000000ULL);
    }
}


TEST_CASE("compute_key_nonce_composite64: key=0xAA..AA, nonce=0xBB..BB → alternating 0xAAAAAAAABBBBBBBB/0xBBBBBBBBAAAAAAAA", "[composite64][mirror_pytest]") {
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


TEST_CASE("init_state_vector64 produces the expected 16-word state", "[init_state_vector64]") {
    constexpr uint64_t entropy[8] = {
        0x0001020304050607ULL, 0x08090A0B0C0D0E0FULL,
        0x1011121314151617ULL, 0x18191A1B1C1D1E1FULL,
        0x2021222324252627ULL, 0x28292A2B2C2D2E2FULL,
        0x3031323334353637ULL, 0x38393A3B3C3D3E3FULL
    };

    constexpr uint64_t max32 = 0xFFFFFFFFULL;
    uint64_t counters[] = {
        0ULL,
        max32 / 2ULL,
        max32 / 3ULL,
        max32
    };

    // 3) All four domain values.
    KDFDomain domains[] = {
        KDFDomain_CTX,
        KDFDomain_MSG,
        KDFDomain_HDR,
        KDFDomain_CHK
    };

    for (const auto domain : domains) {
        const uint64_t d_mask = get_domain_mask64(domain);

        for (const auto ctr64 : counters) {
            uint64_t state[16] = {};

            init_state_vector64(state, entropy, ctr64, domain);

            const auto ctr_low32  = static_cast<uint32_t>(ctr64 & 0xFFFFFFFFu);
            const auto ctr_high32 = static_cast<uint32_t>(ctr64 >> 32 & 0xFFFFFFFFu);

            for (int j = 0; j < 4; j++) {
                REQUIRE(state[j] == IV64[j]);
            }
            for (int j = 12; j < 16; j++) {
                const uint64_t actual = state[j] ^ d_mask;
                REQUIRE(actual == IV64[j - 8]);
            }
            for (int j = 4; j <= 7; j++) {
                const uint64_t recovered = state[j] - static_cast<uint64_t>(ctr_low32);
                REQUIRE(recovered == entropy[j - 4]);
            }
            for (int j = 8; j <= 11; j++) {
                const uint64_t recovered = state[j] - static_cast<uint64_t>(ctr_high32);
                REQUIRE(recovered == entropy[j - 4]);
            }
        }
    }
}