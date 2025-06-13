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
#include "blake_shared.h"
#include "aes_sbox.h"


TEST_CASE("rotr32: rotating by 0 returns the original value", "[unittest][keygen]") {
    REQUIRE(rotr32(0x00000000u, 0) == 0x00000000u);
    REQUIRE(rotr32(0xDEADBEEFu, 0) == 0xDEADBEEFu);
}


TEST_CASE("rotr32: basic rotations", "[unittest][keygen]") {
    SECTION("rotate a single bit from LSB to MSB") {
        uint32_t x = 0x00000001u; // bit0 set
        REQUIRE(rotr32(x, 1) == 0x80000000u);
        REQUIRE(rotr32(x, 2) == 0x40000000u);
        REQUIRE(rotr32(x, 31) == 0x00000002u);
    }

    SECTION("rotate an arbitrary pattern by 8") {
        uint32_t x = 0x12345678u;
        // Expected: 0x78123456
        REQUIRE(rotr32(x, 8) == 0x78123456u);
    }

    SECTION("rotate a pattern by half the word size") {
        uint32_t x = 0xF0F0F0F0u;
        // Rotating by 16 should swap high and low 16-bit halves
        REQUIRE(rotr32(x, 16) == 0xF0F0F0F0u);
    }

    SECTION("rotate by various amounts on 0xAAAAAAAA") {
        uint32_t x = 0xAAAAAAAAu; // alternating bits: 1010...
        REQUIRE(rotr32(x, 1)  == 0x55555555u); // complement pattern
        REQUIRE(rotr32(x, 7)  == 0x55555555u);
        REQUIRE(rotr32(x, 2)  == 0xAAAAAAAAu); // same pattern
        REQUIRE(rotr32(x, 30) == 0xAAAAAAAAu);
    }
}


TEST_CASE("rotr64: rotating by 0 returns the original value", "[unittest][keygen]") {
    REQUIRE(rotr64(0x0000000000000000ULL, 0) == 0x0000000000000000ULL);
    REQUIRE(rotr64(0x0123456789ABCDEFULL, 0) == 0x0123456789ABCDEFULL);
}


TEST_CASE("rotr64: basic rotations", "[unittest][keygen]") {
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


TEST_CASE("init_state_vector32 produces the expected 16-word state", "[unittest][keygen]") {
    constexpr uint32_t entropy[8] = {
        0x00010203u, 0x04050607u, 0x08090A0Bu, 0x0C0D0E0Fu,
        0x10111213u, 0x14151617u, 0x18191A1Bu, 0x1C1D1E1Fu
    };

    constexpr uint64_t max32 = 0xFFFFFFFFULL;
    uint64_t counters[] = {
        0ULL,
        max32 / 2ULL,
        max32 / 3ULL,
        max32
    };

    KDFDomain domains[] = {
        KDFDomain_CTX,
        KDFDomain_MSG,
        KDFDomain_HDR,
        KDFDomain_CHK
    };

    for (const auto domain : domains) {
        const uint32_t d_mask = get_domain_mask32(domain);

        for (const auto ctr64 : counters) {
            uint32_t state[16] = {};

            init_state_vector32(state, entropy, ctr64, domain);

            const auto ctr_low  = static_cast<uint32_t>(ctr64 & 0xFFFFFFFFu);
            const auto ctr_high = static_cast<uint32_t>(ctr64 >> 32 & 0xFFFFFFFFu);

            for (int j = 0; j < 4; j++) {
                REQUIRE(state[j] == IV32[j]);
            }
            for (int j = 12; j < 16; j++) {
                const uint32_t actual = state[j] ^ d_mask;
                REQUIRE(actual == IV32[j - 8]);
            }
            for (int j = 4; j <= 7; j++) {
                const uint32_t recovered = state[j] - ctr_low;
                REQUIRE(recovered == entropy[j - 4]);
            }
            for (int j = 8; j <= 11; j++) {
                const uint32_t recovered = state[j] - ctr_high;
                REQUIRE(recovered == entropy[j - 4]);
            }
        }
    }
}


TEST_CASE("init_state_vector64 produces the expected 16-word state", "[unittest][keygen]") {
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


TEST_CASE("sub_bytes64: DEC (inverse) of 0x6363636363636363 returns zero", "[unittest][keygen]") {
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