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

#include <limits.h>
#include "masking.h"


static const uint8_t BITS_8  = CHAR_BIT * sizeof(uint8_t);
static const uint8_t BITS_32 = CHAR_BIT * sizeof(uint32_t);
static const uint8_t BITS_64 = CHAR_BIT * sizeof(uint64_t);


void dom_bw_rotr8(const uint8_t x[N_SHARES], uint8_t out[N_SHARES], uint8_t n) {
    const uint8_t x0 = x[0], x1 = x[1], x2 = x[2];

    out[0] = x0 >> n | x0 << (BITS_8 - n);
    out[1] = x1 >> n | x1 << (BITS_8 - n);
    out[2] = x2 >> n | x2 << (BITS_8 - n);

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_rotr32(const uint32_t x[N_SHARES], uint32_t out[N_SHARES], uint32_t n) {
    const uint32_t x0 = x[0], x1 = x[1], x2 = x[2];

    out[0] = x0 >> n | x0 << (BITS_32 - n);
    out[1] = x1 >> n | x1 << (BITS_32 - n);
    out[2] = x2 >> n | x2 << (BITS_32 - n);

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_rotr64(const uint64_t x[N_SHARES], uint64_t out[N_SHARES], uint64_t n) {
    const uint64_t x0 = x[0], x1 = x[1], x2 = x[2];

    out[0] = x0 >> n | x0 << (BITS_64 - n);
    out[1] = x1 >> n | x1 << (BITS_64 - n);
    out[2] = x2 >> n | x2 << (BITS_64 - n);

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}