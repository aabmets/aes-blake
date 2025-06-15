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
#include "blake_types.h"
#include "blake_shared.h"


/*
 * Performs the BLAKE3 mixing function on the state matrix using the provided message words.
 * Uses fully unrolled `g_mix` function calls and local registers for optimization.
 */
void blake64_optimized_mix_state(uint64_t state[16], const uint64_t m[16]) {
    uint64_t s0 = state[0];
    uint64_t s1 = state[1];
    uint64_t s2 = state[2];
    uint64_t s3 = state[3];
    uint64_t s4 = state[4];
    uint64_t s5 = state[5];
    uint64_t s6 = state[6];
    uint64_t s7 = state[7];
    uint64_t s8 = state[8];
    uint64_t s9 = state[9];
    uint64_t s10 = state[10];
    uint64_t s11 = state[11];
    uint64_t s12 = state[12];
    uint64_t s13 = state[13];
    uint64_t s14 = state[14];
    uint64_t s15 = state[15];

    s0 = s0 + s4 + m[0];
    s12 = rotr64(s12 ^ s0, 32);
    s8 = s8 + s12;
    s4 = rotr64(s4 ^ s8, 24);

    s0 = s0 + s4 + m[1];
    s12 = rotr64(s12 ^ s0, 16);
    s8 = s8 + s12;
    s4 = rotr64(s4 ^ s8, 63);

    s1 = s1 + s5 + m[2];
    s13 = rotr64(s13 ^ s1, 32);
    s9 = s9 + s13;
    s5 = rotr64(s5 ^ s9, 24);

    s1 = s1 + s5 + m[3];
    s13 = rotr64(s13 ^ s1, 16);
    s9 = s9 + s13;
    s5 = rotr64(s5 ^ s9, 63);

    s2 = s2 + s6 + m[4];
    s14 = rotr64(s14 ^ s2, 32);
    s10 = s10 + s14;
    s6 = rotr64(s6 ^ s10, 24);

    s2 = s2 + s6 + m[5];
    s14 = rotr64(s14 ^ s2, 16);
    s10 = s10 + s14;
    s6 = rotr64(s6 ^ s10, 63);

    s3 = s3 + s7 + m[6];
    s15 = rotr64(s15 ^ s3, 32);
    s11 = s11 + s15;
    s7 = rotr64(s7 ^ s11, 24);

    s3 = s3 + s7 + m[7];
    s15 = rotr64(s15 ^ s3, 16);
    s11 = s11 + s15;
    s7 = rotr64(s7 ^ s11, 63);

    s0 = s0 + s5 + m[8];
    s15 = rotr64(s15 ^ s0, 32);
    s10 = s10 + s15;
    s5 = rotr64(s5 ^ s10, 24);

    s0 = s0 + s5 + m[9];
    s15 = rotr64(s15 ^ s0, 16);
    s10 = s10 + s15;
    s5 = rotr64(s5 ^ s10, 63);

    s1 = s1 + s6 + m[10];
    s12 = rotr64(s12 ^ s1, 32);
    s11 = s11 + s12;
    s6 = rotr64(s6 ^ s11, 24);

    s1 = s1 + s6 + m[11];
    s12 = rotr64(s12 ^ s1, 16);
    s11 = s11 + s12;
    s6 = rotr64(s6 ^ s11, 63);

    s2 = s2 + s7 + m[12];
    s13 = rotr64(s13 ^ s2, 32);
    s8 = s8 + s13;
    s7 = rotr64(s7 ^ s8, 24);

    s2 = s2 + s7 + m[13];
    s13 = rotr64(s13 ^ s2, 16);
    s8 = s8 + s13;
    s7 = rotr64(s7 ^ s8, 63);

    s3 = s3 + s4 + m[14];
    s14 = rotr64(s14 ^ s3, 32);
    s9 = s9 + s14;
    s4 = rotr64(s4 ^ s9, 24);

    s3 = s3 + s4 + m[15];
    s14 = rotr64(s14 ^ s3, 16);
    s9 = s9 + s14;
    s4 = rotr64(s4 ^ s9, 63);

    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = s3;
    state[4] = s4;
    state[5] = s5;
    state[6] = s6;
    state[7] = s7;
    state[8] = s8;
    state[9] = s9;
    state[10] = s10;
    state[11] = s11;
    state[12] = s12;
    state[13] = s13;
    state[14] = s14;
    state[15] = s15;
}


/*
 * Performs the BLAKE3 message permutation on the input message vector.
 * The function reorders a list of BaseUint elements according to the
 * fixed BLAKE3 permutation schedule and returns the permuted list.
 */
void blake64_optimized_permute(uint64_t m[16]) {
    const uint64_t t0  = m[2];
    const uint64_t t1  = m[6];
    const uint64_t t2  = m[3];
    const uint64_t t3  = m[10];
    const uint64_t t4  = m[7];
    const uint64_t t5  = m[0];
    const uint64_t t6  = m[4];
    const uint64_t t7  = m[13];
    const uint64_t t8  = m[1];
    const uint64_t t9  = m[11];
    const uint64_t t10 = m[12];
    const uint64_t t11 = m[5];
    const uint64_t t12 = m[9];
    const uint64_t t13 = m[14];
    const uint64_t t14 = m[15];
    const uint64_t t15 = m[8];

    m[0]  = t0;
    m[1]  = t1;
    m[2]  = t2;
    m[3]  = t3;
    m[4]  = t4;
    m[5]  = t5;
    m[6]  = t6;
    m[7]  = t7;
    m[8]  = t8;
    m[9]  = t9;
    m[10] = t10;
    m[11] = t11;
    m[12] = t12;
    m[13] = t13;
    m[14] = t14;
    m[15] = t15;
}


/**
 * Splices together 8‐element key and nonce arrays of uint64_t by exchanging
 * their upper and lower 32‐bit halves. Produces a 16‐element output array.
 */
void blake64_optimized_compute_knc(
        const uint64_t key[8],
        const uint64_t nonce[8],
        uint64_t out[16]
) {
    const uint64_t mask1 = 0x00000000FFFFFFFFU;
    const uint64_t mask2 = 0xFFFFFFFF00000000U;

    uint64_t k_val;
    uint64_t n_val;

    k_val = key[0], n_val = nonce[0];
    out[0] = k_val & mask2 | n_val & mask1;
    out[1] = n_val & mask2 | k_val & mask1;

    k_val = key[1], n_val = nonce[1];
    out[2] = k_val & mask2 | n_val & mask1;
    out[3] = n_val & mask2 | k_val & mask1;

    k_val = key[2], n_val = nonce[2];
    out[4] = k_val & mask2 | n_val & mask1;
    out[5] = n_val & mask2 | k_val & mask1;

    k_val = key[3], n_val = nonce[3];
    out[6] = k_val & mask2 | n_val & mask1;
    out[7] = n_val & mask2 | k_val & mask1;

    k_val = key[4], n_val = nonce[4];
    out[8] = k_val & mask2 | n_val & mask1;
    out[9] = n_val & mask2 | k_val & mask1;

    k_val = key[5], n_val = nonce[5];
    out[10] = k_val & mask2 | n_val & mask1;
    out[11] = n_val & mask2 | k_val & mask1;

    k_val = key[6], n_val = nonce[6];
    out[12] = k_val & mask2 | n_val & mask1;
    out[13] = n_val & mask2 | k_val & mask1;

    k_val = key[7], n_val = nonce[7];
    out[14] = k_val & mask2 | n_val & mask1;
    out[15] = n_val & mask2 | k_val & mask1;
}


/*
 * Digests the cipher context through ten rounds of compression.
 */
void blake64_optimized_digest_context(
        uint64_t state[16],
        const uint64_t key[8],
        uint64_t context[8]
) {
    blake64_init_state_vector(state, key, 0, KDFDomain_CTX);

    // Round 1
    blake64_optimized_mix_state(state, context);
    blake64_optimized_permute(context);

    // Round 2
    blake64_optimized_mix_state(state, context);
    blake64_optimized_permute(context);

    // Round 3
    blake64_optimized_mix_state(state, context);
    blake64_optimized_permute(context);

    // Round 4
    blake64_optimized_mix_state(state, context);
    blake64_optimized_permute(context);

    // Round 5
    blake64_optimized_mix_state(state, context);
    blake64_optimized_permute(context);

    // Round 6
    blake64_optimized_mix_state(state, context);
    blake64_optimized_permute(context);

    // Round 7
    blake64_optimized_mix_state(state, context);
    blake64_optimized_permute(context);

    // Round 8
    blake64_optimized_mix_state(state, context);
    blake64_optimized_permute(context);

    // Round 9
    blake64_optimized_mix_state(state, context);
    blake64_optimized_permute(context);

    // Round 10
    blake64_optimized_mix_state(state, context);
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
static void compute_round_keys(
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
    blake64_init_state_vector(state_buf, entropy, block_counter, domain);

    // 3) For each round, mix and extract two 128-bit keys
    for (size_t round = 0; round < key_count; round++) {

        // a) Mix key+nonce composite into the state
        blake64_optimized_mix_state(state_buf, knc_local);

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
            blake64_optimized_permute(knc_local);
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
void blake64_optimized_derive_keys(
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
    compute_round_keys(
        entropy1,
        knc,
        key_count,
        block_counter,
        domain,
        out_keys1,
        out_keys2
    );

    // 3) Derive streams #3 and #4 from entropy2
    compute_round_keys(
        entropy2,
        knc,
        key_count,
        block_counter,
        domain,
        out_keys3,
        out_keys4
    );
}