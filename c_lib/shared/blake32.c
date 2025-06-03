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
#include <stddef.h>
#include "aes_sbox.h"


/*
 * Rotates a 32-bit word `x` right by `r` bits. Assumes 0 ≤ r < 32.
 */
uint32_t rotr32(const uint32_t x, const unsigned int r) {
    return (x >> r) | (x << (32 - r));
}


/*
 * Performs the BLAKE3 G‐mix operation on four state vector elements.
 * Uses fixed rotation distances for BLAKE3/32: { 16, 12, 8, 7 }.
 */
void g_mix32(
        uint32_t state[16],
        const int a, const int b, const int c, const int d,
        const uint32_t mx, const uint32_t my
) {
    /* First mixing round */
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);

    /* Second mixing round */
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}


/*
 * Performs the BLAKE3 mixing function on the state matrix using the provided
 * message words. The `g_mix` function is first applied across the columns, then
 * across the diagonals of the state matrix. Each call to `g_mix` uses a pair of
 * message words from the input list.
 */
void mix_into_state32(uint32_t state[16], uint32_t m[16]) {
    // columnar mixing
    g_mix32(state, 0, 4, 8, 12, m[0], m[1]);
    g_mix32(state, 1, 5, 9, 13, m[2], m[3]);
    g_mix32(state, 2, 6, 10, 14, m[4], m[5]);
    g_mix32(state, 3, 7, 11, 15, m[6], m[7]);
    // diagonal mixing
    g_mix32(state, 0, 5, 10, 15, m[8], m[9]);
    g_mix32(state, 1, 6, 11, 12, m[10], m[11]);
    g_mix32(state, 2, 7, 8, 13, m[12], m[13]);
    g_mix32(state, 3, 4, 9, 14, m[14], m[15]);
}


/*
 * Performs the BLAKE3 message permutation on the input message vector.
 * The function reorders a list of BaseUint elements according to the
 * fixed BLAKE3 permutation schedule and returns the permuted list.
 */
void permute32(uint32_t m[16]) {
    const int schedule[16] = {
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
    };
    uint32_t tmp[16];
    for (int i = 0; i < 16; i++) {
        tmp[i] = m[schedule[i]];
    }
    for (int i = 0; i < 16; i++) {
        m[i] = tmp[i];
    }
}


/**
 * Applies AES SubBytes to each word of the state matrix. Each word is split into bytes,
 * each byte is substituted through the AES S-box, and finally they are reassembled back
 * into a word, which then is inserted into the same place in the state matrix.
 */
void sub_bytes32(uint32_t state[16]) {
    for (size_t i = 0; i < 16; i++) {
        const uint32_t v = state[i];

        const uint8_t b0 = (uint8_t)(v >> 24 & 0xFF);
        const uint8_t b1 = (uint8_t)(v >> 16 & 0xFF);
        const uint8_t b2 = (uint8_t)(v >>  8 & 0xFF);
        const uint8_t b3 = (uint8_t)(v       & 0xFF);

        const uint8_t sb0 = aes_sbox[b0];
        const uint8_t sb1 = aes_sbox[b1];
        const uint8_t sb2 = aes_sbox[b2];
        const uint8_t sb3 = aes_sbox[b3];

        state[i] = (uint32_t)sb0 << 24
                 | (uint32_t)sb1 << 16
                 | (uint32_t)sb2 <<  8
                 | (uint32_t)sb3;
    }
}


/**
 * Splices together 8‐element key and nonce arrays of uint32_t by exchanging
 * their upper and lower 16‐bit halves. Produces a 16‐element output array.
 */
void compute_key_nonce_composite32(
        const uint32_t key[8],
        const uint32_t nonce[8],
        uint32_t out[16]
) {
    const int half = 16;
    const uint32_t mask1 = (1u << half) - 1u; // 0x0000FFFF
    const uint32_t mask2 = mask1 << half;     // 0xFFFF0000

    for (size_t i = 0; i < 8; ++i) {
        const uint32_t a = key[i]   & mask2 | nonce[i] & mask1;
        const uint32_t b = nonce[i] & mask2 | key[i]   & mask1;
        out[2*i]     = a;
        out[2*i + 1] = b;
    }
}