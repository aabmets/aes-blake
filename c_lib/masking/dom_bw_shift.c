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
#include "masking.h"

// BITWISE SHIFT

void dom_bw_shiftr8(const uint8_t x[N_SHARES], uint8_t out[N_SHARES], uint8_t n) {
    out[0] = x[0] >> n;
    out[1] = x[1] >> n;
    out[2] = x[2] >> n;

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_shiftr32(const uint32_t x[N_SHARES], uint32_t out[N_SHARES], uint32_t n) {
    out[0] = x[0] >> n;
    out[1] = x[1] >> n;
    out[2] = x[2] >> n;

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_shiftr64(const uint64_t x[N_SHARES], uint64_t out[N_SHARES], uint64_t n) {
    out[0] = x[0] >> n;
    out[1] = x[1] >> n;
    out[2] = x[2] >> n;

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_shiftl8(const uint8_t x[N_SHARES], uint8_t out[N_SHARES], uint8_t n) {
    out[0] = x[0] << n;
    out[1] = x[1] << n;
    out[2] = x[2] << n;

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_shiftl32(const uint32_t x[N_SHARES], uint32_t out[N_SHARES], uint32_t n) {
    out[0] = x[0] << n;
    out[1] = x[1] << n;
    out[2] = x[2] << n;

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_shiftl64(const uint64_t x[N_SHARES], uint64_t out[N_SHARES], uint64_t n) {
    out[0] = x[0] << n;
    out[1] = x[1] << n;
    out[2] = x[2] << n;

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}