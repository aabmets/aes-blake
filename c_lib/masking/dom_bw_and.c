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

#include "csprng.h"
#include "masking.h"


void dom_bw_and8(const uint8_t x[N_SHARES], const uint8_t y[N_SHARES], uint8_t out[N_SHARES]) {
    // --- Generate randomness ---
    uint8_t rand[N_SHARES];
    csprng_read_array(rand, N_SHARES);
    const uint8_t r01 = rand[0], r02 = rand[1], r12 = rand[2];

    // --- Load input shares into local variables ---
    const uint8_t x0 = x[0], x1 = x[1], x2 = x[2];
    const uint8_t y0 = y[0], y1 = y[1], y2 = y[2];

    // --- Resharing phase (computation) ---
    const uint8_t p01_masked = x0 & y1 ^ r01;
    const uint8_t p10_masked = x1 & y0 ^ r01;

    const uint8_t p02_masked = x0 & y2 ^ r02;
    const uint8_t p20_masked = x2 & y0 ^ r02;

    const uint8_t p12_masked = x1 & y2 ^ r12;
    const uint8_t p21_masked = x2 & y1 ^ r12;

    // --- Integration phase ---
    out[0] = x0 & y0 ^ p01_masked ^ p02_masked;
    out[1] = x1 & y1 ^ p10_masked ^ p12_masked;
    out[2] = x2 & y2 ^ p20_masked ^ p21_masked;

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_and32(const uint32_t x[N_SHARES], const uint32_t y[N_SHARES], uint32_t out[N_SHARES]) {
    // --- Generate randomness ---
    uint32_t rand[N_SHARES];
    csprng_read_array((uint8_t*)rand, sizeof(rand));
    const uint32_t r01 = rand[0], r02 = rand[1], r12 = rand[2];

    // --- Load input shares into local variables ---
    const uint32_t x0 = x[0], x1 = x[1], x2 = x[2];
    const uint32_t y0 = y[0], y1 = y[1], y2 = y[2];

    // --- Resharing phase (computation) ---
    const uint32_t p01_masked = x0 & y1 ^ r01;
    const uint32_t p10_masked = x1 & y0 ^ r01;

    const uint32_t p02_masked = x0 & y2 ^ r02;
    const uint32_t p20_masked = x2 & y0 ^ r02;

    const uint32_t p12_masked = x1 & y2 ^ r12;
    const uint32_t p21_masked = x2 & y1 ^ r12;

    // --- Integration phase ---
    out[0] = x0 & y0 ^ p01_masked ^ p02_masked;
    out[1] = x1 & y1 ^ p10_masked ^ p12_masked;
    out[2] = x2 & y2 ^ p20_masked ^ p21_masked;

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_and64(const uint64_t x[N_SHARES], const uint64_t y[N_SHARES], uint64_t out[N_SHARES]) {
    // --- Generate randomness ---
    uint64_t rand[N_SHARES];
    csprng_read_array((uint8_t*)rand, sizeof(rand));
    const uint64_t r01 = rand[0], r02 = rand[1], r12 = rand[2];

    // --- Load input shares into local variables ---
    const uint64_t x0 = x[0], x1 = x[1], x2 = x[2];
    const uint64_t y0 = y[0], y1 = y[1], y2 = y[2];

    // --- Resharing phase (computation) ---
    const uint64_t p01_masked = x0 & y1 ^ r01;
    const uint64_t p10_masked = x1 & y0 ^ r01;

    const uint64_t p02_masked = x0 & y2 ^ r02;
    const uint64_t p20_masked = x2 & y0 ^ r02;

    const uint64_t p12_masked = x1 & y2 ^ r12;
    const uint64_t p21_masked = x2 & y1 ^ r12;

    // --- Integration phase ---
    out[0] = x0 & y0 ^ p01_masked ^ p02_masked;
    out[1] = x1 & y1 ^ p10_masked ^ p12_masked;
    out[2] = x2 & y2 ^ p20_masked ^ p21_masked;

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}