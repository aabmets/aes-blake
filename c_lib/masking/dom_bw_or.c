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

// BITWISE OR

void dom_bw_or8(const uint8_t x[N_SHARES], const uint8_t y[N_SHARES], uint8_t out[N_SHARES]) {
    // Based on the identity: a | b = (a ^ b) ^ (a & b).
    uint8_t and_shares[N_SHARES];
    dom_bw_and8(x, y, and_shares);

    // Combine the results: out = (x ^ y) ^ (x & y)
    out[0] = x[0] ^ y[0] ^ and_shares[0];
    out[1] = x[1] ^ y[1] ^ and_shares[1];
    out[2] = x[2] ^ y[2] ^ and_shares[2];

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_or32(const uint32_t x[N_SHARES], const uint32_t y[N_SHARES], uint32_t out[N_SHARES]) {
    // Based on the identity: a | b = (a ^ b) ^ (a & b).
    uint32_t and_shares[N_SHARES];
    dom_bw_and32(x, y, and_shares);

    // Combine the results: out = (x ^ y) ^ (x & y)
    out[0] = x[0] ^ y[0] ^ and_shares[0];
    out[1] = x[1] ^ y[1] ^ and_shares[1];
    out[2] = x[2] ^ y[2] ^ and_shares[2];

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}


void dom_bw_or64(const uint64_t x[N_SHARES], const uint64_t y[N_SHARES], uint64_t out[N_SHARES]) {
    // Based on the identity: a | b = (a ^ b) ^ (a & b).
    uint64_t and_shares[N_SHARES];
    dom_bw_and64(x, y, and_shares);

    // Combine the results: out = (x ^ y) ^ (x & y)
    out[0] = x[0] ^ y[0] ^ and_shares[0];
    out[1] = x[1] ^ y[1] ^ and_shares[1];
    out[2] = x[2] ^ y[2] ^ and_shares[2];

    // --- Compiler memory barrier ---
    asm volatile ("" ::: "memory");
}
