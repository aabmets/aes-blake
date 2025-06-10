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

#include <stdint.h>
#include <stdbool.h>
#include "aes_sbox.h"
#include "aes_utils.h"


void transpose_state_matrix(uint8_t state[16]) {
    uint32_t *ptr = (uint32_t*)state;
    const uint32_t buf0 = ptr[0];
    const uint32_t buf1 = ptr[1];
    const uint32_t buf2 = ptr[2];
    const uint32_t buf3 = ptr[3];

    ptr[0] = buf0       & 0x000000FF
           | buf1 <<  8 & 0x0000FF00
           | buf2 << 16 & 0x00FF0000
           | buf3 << 24 & 0xFF000000;

    ptr[1] = buf0 >>  8 & 0x000000FF
           | buf1       & 0x0000FF00
           | buf2 <<  8 & 0x00FF0000
           | buf3 << 16 & 0xFF000000;

    ptr[2] = buf0 >> 16 & 0x000000FF
           | buf1 >>  8 & 0x0000FF00
           | buf2       & 0x00FF0000
           | buf3 <<  8 & 0xFF000000;

    ptr[3] = buf0 >> 24 & 0x000000FF
           | buf1 >> 16 & 0x0000FF00
           | buf2 >>  8 & 0x00FF0000
           | buf3       & 0xFF000000;
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


void generate_enc_tables(
        uint32_t Te0[256],
        uint32_t Te1[256],
        uint32_t Te2[256],
        uint32_t Te3[256],
        const bool little_endian
) {
    for (int i = 0; i < 256; i++) {
        uint32_t t0, t1, t2, t3;
        compute_enc_table_words(i, &t0, &t1, &t2, &t3, little_endian);

        Te0[i] = t0;
        Te1[i] = t1;
        Te2[i] = t2;
        Te3[i] = t3;
    }
}


void compute_enc_table_words(
        const uint8_t index,
        uint32_t *t0,
        uint32_t *t1,
        uint32_t *t2,
        uint32_t *t3,
        const bool little_endian
) {
    const uint8_t s1 = aes_sbox[index];
    const uint8_t s2 = xtime(s1);
    const uint8_t s3 = s2 ^ s1;

    *t0 = (uint32_t)s2 << 24
        | (uint32_t)s1 << 16
        | (uint32_t)s1 << 8
        | (uint32_t)s3;

    *t1 = (uint32_t)s3 << 24
        | (uint32_t)s2 << 16
        | (uint32_t)s1 << 8
        | (uint32_t)s1;

    *t2 = (uint32_t)s1 << 24
        | (uint32_t)s3 << 16
        | (uint32_t)s2 << 8
        | (uint32_t)s1;

    *t3 = (uint32_t)s1 << 24
        | (uint32_t)s1 << 16
        | (uint32_t)s3 <<  8
        | (uint32_t)s2;

    if (little_endian)  {
        *t0 = __builtin_bswap32(*t0);
        *t1 = __builtin_bswap32(*t1);
        *t2 = __builtin_bswap32(*t2);
        *t3 = __builtin_bswap32(*t3);
    }
}
