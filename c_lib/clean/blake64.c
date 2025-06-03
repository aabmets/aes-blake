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
 * Performs the BLAKE3 mixing function on the state matrix using the provided
 * message words. The `g_mix` function is first applied across the columns, then
 * across the diagonals of the state matrix. Each call to `g_mix` uses a pair of
 * message words from the input list.
 */
void mix_into_state64(uint64_t state[16], uint64_t m[16]) {
    // columnar mixing
    g_mix64(state, 0, 4, 8, 12, m[0], m[1]);
    g_mix64(state, 1, 5, 9, 13, m[2], m[3]);
    g_mix64(state, 2, 6, 10, 14, m[4], m[5]);
    g_mix64(state, 3, 7, 11, 15, m[6], m[7]);
    // diagonal mixing
    g_mix64(state, 0, 5, 10, 15, m[8], m[9]);
    g_mix64(state, 1, 6, 11, 12, m[10], m[11]);
    g_mix64(state, 2, 7, 8, 13, m[12], m[13]);
    g_mix64(state, 3, 4, 9, 14, m[14], m[15]);
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
