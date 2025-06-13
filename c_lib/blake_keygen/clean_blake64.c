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
#include "blake_shared.h"


/*
 * Performs the BLAKE3 G‐mix operation on four state vector elements.
 * Uses fixed rotation distances for BLAKE3/64: { 32, 24, 16, 63 }.
 */
void g_mix64(
        uint64_t state[16],
        const uint8_t a,
        const uint8_t b,
        const uint8_t c,
        const uint8_t d,
        const uint64_t mx,
        const uint64_t my
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
 * Splices together 8‐element key and nonce arrays of uint64_t by exchanging
 * their upper and lower 32‐bit halves. Produces a 16‐element output array.
 */
void compute_key_nonce_composite64(
        const uint64_t key[8],
        const uint64_t nonce[8],
        uint64_t out[16]
) {
    const uint64_t mask1 = 0x00000000FFFFFFFFU;
    const uint64_t mask2 = 0xFFFFFFFF00000000U;

    uint64_t k_val;
    uint64_t n_val;

    for (size_t i = 0; i < 8; ++i) {
        k_val = key[i], n_val = nonce[i];
        out[2*i]     = k_val & mask2 | n_val & mask1;
        out[2*i + 1] = n_val & mask2 | k_val & mask1;
    }
}


/*
 * Digests the cipher context through ten rounds of compression.
 */
void digest_context64(
        uint64_t state[16],
        const uint64_t key[8],
        uint64_t context[8]
) {
    init_state_vector64(state, key, 0, KDFDomain_CTX);
    for (int i = 0; i < 9; i++) {
        mix_into_state64(state, context);
        permute64(context);
    }
    mix_into_state64(state, context);
    sub_bytes64(state);
}


/*
 * derive_keys64 helper: Generates `key_count` 128‐bit round keys.
 *   - entropy[8]:     eight 64‐bit words
 *   - knc[16]:        precomputed key+nonce composite
 *   - key_count:      number of round keys to output
 *   - block_counter:  64‐bit counter for init_state_vector64
 *   - domain:         KDFDomain for domain separation
 *   - out_keys[][16]: output buffer for 128‐bit keys
 */
static void compute_round_keys64(
        const uint64_t entropy[8],
        const uint64_t knc[16],
        const size_t key_count,
        const uint64_t block_counter,
        const KDFDomain domain,
        uint8_t out_keys1[][16],
        uint8_t out_keys2[][16]
) {
    uint64_t state_buf[16];
    uint64_t knc_local[16];

    // 1) Copy master knc[] into the local buffer
    for (int i = 0; i < 16; i++) {
        knc_local[i] = knc[i];
    }

    // 2) Initialize BLAKE state from this entropy, counter, and domain
    init_state_vector64(state_buf, entropy, block_counter, domain);

    // 3) For each round, mix and extract two 128-bit keys
    for (size_t round = 0; round < key_count; round++) {

        // a) Mix key+nonce composite into the state
        mix_into_state64(state_buf, knc_local);

        // b) Extract state_buf[4..5] → out_keys1[round][0..15]
        for (int w = 0; w < 2; w++) {
            const uint64_t v = state_buf[4 + w];
            out_keys1[round][8*w + 0] = (uint8_t)(v >> 56);
            out_keys1[round][8*w + 1] = (uint8_t)(v >> 48);
            out_keys1[round][8*w + 2] = (uint8_t)(v >> 40);
            out_keys1[round][8*w + 3] = (uint8_t)(v >> 32);
            out_keys1[round][8*w + 4] = (uint8_t)(v >> 24);
            out_keys1[round][8*w + 5] = (uint8_t)(v >> 16);
            out_keys1[round][8*w + 6] = (uint8_t)(v >>  8);
            out_keys1[round][8*w + 7] = (uint8_t)(v      );
        }

        // c) Extract state_buf[6..7] → out_keys2[round][0..15]
        for (int w = 0; w < 2; w++) {
            const uint64_t v = state_buf[6 + w];
            out_keys2[round][8*w + 0] = (uint8_t)(v >> 56);
            out_keys2[round][8*w + 1] = (uint8_t)(v >> 48);
            out_keys2[round][8*w + 2] = (uint8_t)(v >> 40);
            out_keys2[round][8*w + 3] = (uint8_t)(v >> 32);
            out_keys2[round][8*w + 4] = (uint8_t)(v >> 24);
            out_keys2[round][8*w + 5] = (uint8_t)(v >> 16);
            out_keys2[round][8*w + 6] = (uint8_t)(v >>  8);
            out_keys2[round][8*w + 7] = (uint8_t)(v      );
        }

        // d) Permute knc_local for the next round (unless this was the last round)
        if (round + 1 < key_count) {
            permute64(knc_local);
        }
    }
}


/**
 * derive_keys64:
 *   - init_state[16]:  precomputed 16‐word BLAKE state
 *   - knc[16]:         precomputed key+nonce composite
 *   - key_count:       number of 128‐bit keys per stream
 *   - block_counter:   64‐bit counter for init_state_vector64
 *   - domain:          KDFDomain for domain separation
 *   - out_keys1[][16]: output buffer for stream #1
 *   - out_keys2[][16]: output buffer for stream #2
 *   - out_keys3[][16]: output buffer for stream #3
 *   - out_keys4[][16]: output buffer for stream #4
 */
void derive_keys64(
        const uint64_t init_state[16],
        const uint64_t knc[16],
        const uint8_t key_count,
        const uint64_t block_counter,
        const KDFDomain domain,
        uint8_t out_keys1[][16],
        uint8_t out_keys2[][16],
        uint8_t out_keys3[][16],
        uint8_t out_keys4[][16]
) {
    // 1) Build two 8-word entropy arrays from init_state
    uint64_t entropy1[8];
    uint64_t entropy2[8];
    for (int i = 0; i < 4; i++) {
        entropy1[i]      = init_state[i];
        entropy2[i]      = init_state[4 + i];
        entropy1[4 + i]  = init_state[8 + i];
        entropy2[4 + i]  = init_state[12 + i];
    }

    // 2) Derive streams #1 and #2 from entropy1
    compute_round_keys64(
        entropy1,
        knc,
        key_count,
        block_counter,
        domain,
        out_keys1,
        out_keys2
    );

    // 3) Derive streams #3 and #4 from entropy2
    compute_round_keys64(
        entropy2,
        knc,
        key_count,
        block_counter,
        domain,
        out_keys3,
        out_keys4
    );
}