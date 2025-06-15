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

#include "masking.h"

// BITWISE NOT

void dom_bw_not8(const uint8_t x[N_SHARES], uint8_t out[N_SHARES]) {
    out[0] = ~x[0];
    out[1] = x[1];
    out[2] = x[2];

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_not32(const uint32_t x[N_SHARES], uint32_t out[N_SHARES]) {
    out[0] = ~x[0];
    out[1] = x[1];
    out[2] = x[2];

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_not64(const uint64_t x[N_SHARES], uint64_t out[N_SHARES]) {
    out[0] = ~x[0];
    out[1] = x[1];
    out[2] = x[2];

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}