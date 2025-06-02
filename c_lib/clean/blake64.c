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


/*
 * Rotates a 64-bit word `x` right by `r` bits. Assumes 0 ≤ r < 64.
 */
uint64_t rotr64(const uint64_t x, const unsigned int r) {
    return (x >> r) | (x << (64 - r));
}


/*
 * Performs the BLAKE3 G‐mix operation on four state vector elements.
 * Uses fixed rotation distances for BLAKE3/64: { 32, 24, 16, 63 }.
 */
void g_mix64(
        uint64_t state[16],
        const int a, const int b, const int c, const int d,
        const uint64_t mx, const uint64_t my
) {
    /* First mixing round */
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr64(state[d] ^ state[a], 32);
    state[c] = state[c] + state[d];
    state[b] = rotr64(state[b] ^ state[c], 24);

    /* Second mixing round */
    state[a] = state[a] + state[b] + my;
    state[d] = rotr64(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr64(state[b] ^ state[c], 63);
}


/*
 * Performs the BLAKE3 message permutation on the input message vector.
 * The function reorders a list of BaseUint elements according to the
 * fixed BLAKE3 permutation schedule and returns the permuted list.
 */
void permute64(uint64_t m[16]) {
    const int schedule[16] = {
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
    };
    uint64_t tmp[16];
    for (int i = 0; i < 16; i++) {
        tmp[i] = m[schedule[i]];
    }
    for (int i = 0; i < 16; i++) {
        m[i] = tmp[i];
    }
}
