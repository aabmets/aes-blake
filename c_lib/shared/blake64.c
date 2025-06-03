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


/**
 * Applies AES SubBytes to each word of the state matrix. Each word is split into bytes,
 * each byte is substituted through the AES S-box, and finally they are reassembled back
 * into a word, which then is inserted into the same place in the state matrix.
 */
void sub_bytes64(uint64_t state[16]) {
    for (size_t i = 0; i < 16; i++) {
        const uint64_t v = state[i];

        const uint8_t b0 = (uint8_t)(v >> 56 & 0xFF);
        const uint8_t b1 = (uint8_t)(v >> 48 & 0xFF);
        const uint8_t b2 = (uint8_t)(v >> 40 & 0xFF);
        const uint8_t b3 = (uint8_t)(v >> 32 & 0xFF);
        const uint8_t b4 = (uint8_t)(v >> 24 & 0xFF);
        const uint8_t b5 = (uint8_t)(v >> 16 & 0xFF);
        const uint8_t b6 = (uint8_t)(v >>  8 & 0xFF);
        const uint8_t b7 = (uint8_t)(v       & 0xFF);

        const uint8_t sb0 = aes_sbox[b0];
        const uint8_t sb1 = aes_sbox[b1];
        const uint8_t sb2 = aes_sbox[b2];
        const uint8_t sb3 = aes_sbox[b3];
        const uint8_t sb4 = aes_sbox[b4];
        const uint8_t sb5 = aes_sbox[b5];
        const uint8_t sb6 = aes_sbox[b6];
        const uint8_t sb7 = aes_sbox[b7];

        state[i] = (uint64_t)sb0 << 56
                 | (uint64_t)sb1 << 48
                 | (uint64_t)sb2 << 40
                 | (uint64_t)sb3 << 32
                 | (uint64_t)sb4 << 24
                 | (uint64_t)sb5 << 16
                 | (uint64_t)sb6 <<  8
                 | (uint64_t)sb7;
    }
}


/**
 * Splices together 8‐element key and nonce arrays of uint64_t by exchanging
 * their upper and lower 32‐bit halves. Produces a 16‐element output array.
 */
void compute_key_nonce_composite64(
        const uint64_t key[8],
        const uint64_t nonce[8],
        uint64_t out[16]
) {
    const int half = 32;
    const uint64_t mask1 = (1ULL << half) - 1ULL; // 0x00000000FFFFFFFF
    const uint64_t mask2 = mask1 << half;         // 0xFFFFFFFF00000000

    for (size_t i = 0; i < 8; ++i) {
        const uint64_t a = (key[i]   & mask2) | (nonce[i] & mask1);
        const uint64_t b = (nonce[i] & mask2) | (key[i]   & mask1);
        out[2*i]     = a;
        out[2*i + 1] = b;
    }
}