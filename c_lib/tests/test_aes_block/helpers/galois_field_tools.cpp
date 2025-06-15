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

#include <cstdint>
#include "aes_sbox.h"
#include "helpers.h"


uint8_t xtime(const uint8_t x) {
    return static_cast<uint8_t>(x << 1 ^ (x >> 7) * 0x1B);
}


uint8_t gf_mul(uint8_t x, uint8_t y) {
    uint8_t r = 0;
    for (uint8_t i = 0; i < 8; i++) {
        if (y & 1) r ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return r;
}


uint8_t gf_inv(const uint8_t x) {
    if (!x) return 0;
    uint8_t result = 1;
    uint8_t base = x;
    uint8_t exp = 254; // Since x^(254) equals the inverse in GF(2^8)
    while (exp) {
        if (exp & 1)
            result = gf_mul(result, base);
        base = gf_mul(base, base);
        exp >>= 1;
    }
    return result;
}


uint8_t compute_sbox(const uint8_t x) {
    const uint8_t inv = gf_inv(x);
    uint8_t y = inv;
    y ^= (inv << 1) | (inv >> 7);
    y ^= (inv << 2) | (inv >> 6);
    y ^= (inv << 3) | (inv >> 5);
    y ^= (inv << 4) | (inv >> 4);
    y ^= 0x63;
    return y;
}


void compute_enc_table_words(
        const uint8_t x,
        uint32_t *t0,
        uint32_t *t1,
        uint32_t *t2,
        uint32_t *t3,
        const bool little_endian
) {
    const uint8_t s1 = aes_sbox[x];
    const uint8_t s2 = xtime(s1);
    const uint8_t s3 = s2 ^ s1;

    *t0 = s2 << 24 | s1 << 16 | s1 << 8 | s3;
    *t1 = s3 << 24 | s2 << 16 | s1 << 8 | s1;
    *t2 = s1 << 24 | s3 << 16 | s2 << 8 | s1;
    *t3 = s1 << 24 | s1 << 16 | s3 << 8 | s2;

    if (little_endian)  {
        *t0 = __builtin_bswap32(*t0);
        *t1 = __builtin_bswap32(*t1);
        *t2 = __builtin_bswap32(*t2);
        *t3 = __builtin_bswap32(*t3);
    }
}


void generate_enc_tables(
        uint32_t Te0[256],
        uint32_t Te1[256],
        uint32_t Te2[256],
        uint32_t Te3[256],
        const bool little_endian
) {
    for (int x = 0; x < 256; x++) {
        uint32_t t0, t1, t2, t3;
        compute_enc_table_words(x, &t0, &t1, &t2, &t3, little_endian);

        Te0[x] = t0;
        Te1[x] = t1;
        Te2[x] = t2;
        Te3[x] = t3;
    }
}


void compute_imc_table_words(
        const uint8_t x,
        uint32_t *t0,
        uint32_t *t1,
        uint32_t *t2,
        uint32_t *t3,
        const bool little_endian
) {
    const uint8_t x2 = xtime(x);   // 2·x
    const uint8_t x4 = xtime(x2);  // 4·x
    const uint8_t x8 = xtime(x4);  // 8·x

    const uint32_t m9  = x8 ^ x;        // 9·x = 8·x ⊕ x
    const uint32_t m11 = x8 ^ x2 ^ x;   // 11·x = 8·x ⊕ 2·x ⊕ x
    const uint32_t m13 = x8 ^ x4 ^ x;   // 13·x = 8·x ⊕ 4·x ⊕ x
    const uint32_t m14 = x8 ^ x4 ^ x2;  // 14·x = 8·x ⊕ 4·x ⊕ 2·x

    *t0 = m11 | m13 <<  8 | m9  << 16 | m14 << 24;
    *t1 = m13 | m9  <<  8 | m14 << 16 | m11 << 24;
    *t2 = m9  | m14 <<  8 | m11 << 16 | m13 << 24;
    *t3 = m14 | m11 <<  8 | m13 << 16 | m9  << 24;

    if (little_endian)  {
        *t0 = __builtin_bswap32(*t0);
        *t1 = __builtin_bswap32(*t1);
        *t2 = __builtin_bswap32(*t2);
        *t3 = __builtin_bswap32(*t3);
    }
}


void generate_imc_tables(
        uint32_t IMC0[256],
        uint32_t IMC1[256],
        uint32_t IMC2[256],
        uint32_t IMC3[256],
        const bool little_endian
) {
    for (uint8_t x = 0; x < 256; x++) {
        uint32_t t0, t1, t2, t3;
        compute_imc_table_words(x, &t0, &t1, &t2, &t3, little_endian);

        IMC0[x] = t0;
        IMC1[x] = t1;
        IMC2[x] = t2;
        IMC3[x] = t3;
    }
}