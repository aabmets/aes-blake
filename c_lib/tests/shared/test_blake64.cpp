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


TEST_CASE("digest_context64 produces expected final state", "[digest_context64]") {
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


TEST_CASE("derive_keys64 matches Python test vectors", "[derive_keys64]") {
    // 1) Prepare a zeroed key[8] and zeroed nonce/context[8].
    uint64_t zero_key[8]   = {};
    uint64_t zero_nonce[8] = {};

    // 2) Compute the initial state by “digesting the context” (all‐zero key/nonce).
    uint64_t init_state[16] = {};
    digest_context64(init_state, zero_key, zero_nonce);

    // 3) Compute knc[16] via compute_key_nonce_composite64(zero_key, zero_nonce, knc).
    uint64_t knc[16];
    compute_key_nonce_composite64(zero_key, zero_nonce, knc);

    // 4) We will derive key_count=10 round‐keys for counters 0, 1, 2 and domains MSG, HDR, CHK.
    constexpr size_t key_count = 10;
    uint8_t out_keys1[key_count][16];
    uint8_t out_keys2[key_count][16];
    uint8_t out_keys3[key_count][16];
    uint8_t out_keys4[key_count][16];

    // 5) Expected first‐round outputs (Python pytest):
    struct Expected {
        KDFDomain domain;
        uint64_t  counter;
        uint8_t   expected_k1[16];
        uint8_t   expected_k2[16];
        uint8_t   expected_k3[16];
        uint8_t   expected_k4[16];
    };

    Expected cases[] = {
        {
            KDFDomain_MSG,
            0ULL,
            {  // expected_k1 for (domain=MSG, counter=0)
                0x00, 0xAA, 0x3C, 0xEE,
                0xB1, 0xB0, 0x6B, 0x31,
                0xA8, 0x96, 0xF5, 0xFC,
                0x99, 0x6F, 0x6A, 0xA8
            },
            {  // expected_k2 for (domain=MSG, counter=0)
                0x2E, 0x9A, 0xB4, 0x00,
                0x84, 0x28, 0xAD, 0x9B,
                0xEE, 0xD4, 0xEC, 0x6F,
                0xB8, 0xBC, 0xF1, 0x4D
            },
            {  // expected_k3 for (domain=MSG, counter=0)
                0xEF, 0x8B, 0x07, 0x15,
                0x1D, 0xFF, 0xCF, 0xF8,
                0x8D, 0xDD, 0x46, 0x7E,
                0x03, 0x34, 0x60, 0x56
            },
            {  // expected_k4 for (domain=MSG, counter=0)
                0x30, 0xE4, 0x06, 0x92,
                0xBE, 0x31, 0x69, 0xFA,
                0x29, 0xF3, 0xB0, 0x3D,
                0x65, 0x9F, 0x2F, 0x60
            }
        },
        {
            KDFDomain_HDR,
            1ULL,
            {  // expected_k1 for (domain=HDR, counter=1)
                0xA7, 0x33, 0x26, 0x81,
                0x2D, 0x13, 0xEA, 0xC9,
                0xED, 0xEF, 0x73, 0xDD,
                0xC6, 0xBF, 0x3B, 0x8F
            },
            {  // expected_k2 for (domain=HDR, counter=1)
                0xA8, 0x4A, 0xC8, 0xDE,
                0xB0, 0x55, 0xBE, 0xA4,
                0xD3, 0x2D, 0x62, 0x65,
                0x39, 0x2F, 0xC5, 0x63
            },
            {  // expected_k3 for (domain=HDR, counter=1)
                0x2E, 0xA7, 0xFF, 0x38,
                0x7A, 0x06, 0x29, 0x9A,
                0x0B, 0xDF, 0xE9, 0x50,
                0xA6, 0xCD, 0xB0, 0x96
            },
            {  // expected_k4 for (domain=HDR, counter=1)
                0xFF, 0x6A, 0x7D, 0x2D,
                0x84, 0xCD, 0xB4, 0x9C,
                0x9F, 0x8B, 0xA6, 0x0C,
                0xCA, 0x83, 0x1A, 0xEA
            }
        },
        {
            KDFDomain_CHK,
            2ULL,
            {  // expected_k1 for (domain=CHK, counter=2)
                0xFF, 0x70, 0xF1, 0x92,
                0xE7, 0xBD, 0x58, 0x85,
                0x37, 0x23, 0xA7, 0x3B,
                0xBA, 0x6D, 0x55, 0xE6
            },
            {  // expected_k2 for (domain=CHK, counter=2)
                0xFE, 0xC0, 0xAA, 0x27,
                0x03, 0xBA, 0x02, 0x63,
                0xD3, 0x07, 0x58, 0x90,
                0x8E, 0x6F, 0xB6, 0x2C
            },
            {  // expected_k3 for (domain=CHK, counter=2)
                0x93, 0x42, 0xC4, 0x88,
                0xB6, 0x5D, 0xD3, 0x9D,
                0xE8, 0x16, 0xB6, 0x0B,
                0x84, 0xF1, 0xC7, 0x1E
            },
            {  // expected_k4 for (domain=CHK, counter=2)
                0x24, 0xB8, 0xBC, 0x9C,
                0x08, 0x2F, 0x0B, 0xBE,
                0x0B, 0xA9, 0x66, 0x6A,
                0xC5, 0xC4, 0xB8, 0x87
            }
        }
    };

    for (const auto& [
            domain,
            counter,
            expected_k1,
            expected_k2,
            expected_k3,
            expected_k4
        ] : cases) {

        // 6) Call derive_keys64
        derive_keys64(
            init_state,
            knc,
            key_count,
            counter,
            domain,
            out_keys1,
            out_keys2,
            out_keys3,
            out_keys4
        );

        // 7) Verify that out_keys1[0], out_keys2[0], out_keys3[0] and out_keys4[0]
        //    match the expected arrays for this test case.
        for (int i = 0; i < 16; i++) {
            REQUIRE(out_keys1[0][i] == expected_k1[i]);
            REQUIRE(out_keys2[0][i] == expected_k2[i]);
            REQUIRE(out_keys3[0][i] == expected_k3[i]);
            REQUIRE(out_keys4[0][i] == expected_k4[i]);
        }
    }
}