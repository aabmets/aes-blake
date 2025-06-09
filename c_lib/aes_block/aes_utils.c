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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "aes_sbox.h"
#include "aes_utils.h"


uint8_t gf_mul(uint8_t x, uint8_t y) {
    uint8_t r = 0;
    for (uint8_t i = 0; i < 8; i++) {
        if (y & 1) r ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return r;
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


static void print_state(const uint8_t state[16], const char* sep) {
    printf("\n");
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            printf("%02X ", state[row * 4 + col]);
        }
        if (row < 3) {
            printf("%s", sep);
        }
    }
    printf("\n");
}


void print_state_matrix(uint8_t state[16]) {
    print_state(state, "\n");
}


void print_state_vector(uint8_t state[16]) {
    print_state(state, " ");
}


static void words_into_state(
        uint8_t state[16],
        const uint32_t w0,
        const uint32_t w1,
        const uint32_t w2,
        const uint32_t w3
) {
    for (int i = 0; i < 4; ++i) {
        state[i     ] = (uint8_t)(w0 >> (8 * i));
        state[i + 4 ] = (uint8_t)(w1 >> (8 * i));
        state[i + 8 ] = (uint8_t)(w2 >> (8 * i));
        state[i + 12] = (uint8_t)(w3 >> (8 * i));
    }
}


void print_words_matrix(const uint32_t w0, const uint32_t w1, const uint32_t w2, const uint32_t w3) {
    uint8_t state[16];
    words_into_state(state, w0, w1, w2, w3);
    print_state(state, "\n");
}


void print_words_vector(const uint32_t w0, const uint32_t w1, const uint32_t w2, const uint32_t w3) {
    uint8_t state[16];
    words_into_state(state, w0, w1, w2, w3);
    print_state(state, " ");
}
