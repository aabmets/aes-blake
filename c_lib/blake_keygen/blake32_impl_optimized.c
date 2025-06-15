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
void blake32_optimized_mix_state(uint32_t state[16], const uint32_t m[16]) {
    uint32_t s0 = state[0];
    uint32_t s1 = state[1];
    uint32_t s2 = state[2];
    uint32_t s3 = state[3];
    uint32_t s4 = state[4];
    uint32_t s5 = state[5];
    uint32_t s6 = state[6];
    uint32_t s7 = state[7];
    uint32_t s8 = state[8];
    uint32_t s9 = state[9];
    uint32_t s10 = state[10];
    uint32_t s11 = state[11];
    uint32_t s12 = state[12];
    uint32_t s13 = state[13];
    uint32_t s14 = state[14];
    uint32_t s15 = state[15];

    s0 = s0 + s4 + m[0];
    s12 = rotr32(s12 ^ s0, 16);
    s8 = s8 + s12;
    s4 = rotr32(s4 ^ s8, 12);

    s0 = s0 + s4 + m[1];
    s12 = rotr32(s12 ^ s0, 8);
    s8 = s8 + s12;
    s4 = rotr32(s4 ^ s8, 7);

    s1 = s1 + s5 + m[2];
    s13 = rotr32(s13 ^ s1, 16);
    s9 = s9 + s13;
    s5 = rotr32(s5 ^ s9, 12);

    s1 = s1 + s5 + m[3];
    s13 = rotr32(s13 ^ s1, 8);
    s9 = s9 + s13;
    s5 = rotr32(s5 ^ s9, 7);

    s2 = s2 + s6 + m[4];
    s14 = rotr32(s14 ^ s2, 16);
    s10 = s10 + s14;
    s6 = rotr32(s6 ^ s10, 12);

    s2 = s2 + s6 + m[5];
    s14 = rotr32(s14 ^ s2, 8);
    s10 = s10 + s14;
    s6 = rotr32(s6 ^ s10, 7);

    s3 = s3 + s7 + m[6];
    s15 = rotr32(s15 ^ s3, 16);
    s11 = s11 + s15;
    s7 = rotr32(s7 ^ s11, 12);

    s3 = s3 + s7 + m[7];
    s15 = rotr32(s15 ^ s3, 8);
    s11 = s11 + s15;
    s7 = rotr32(s7 ^ s11, 7);

    s0 = s0 + s5 + m[8];
    s15 = rotr32(s15 ^ s0, 16);
    s10 = s10 + s15;
    s5 = rotr32(s5 ^ s10, 12);

    s0 = s0 + s5 + m[9];
    s15 = rotr32(s15 ^ s0, 8);
    s10 = s10 + s15;
    s5 = rotr32(s5 ^ s10, 7);

    s1 = s1 + s6 + m[10];
    s12 = rotr32(s12 ^ s1, 16);
    s11 = s11 + s12;
    s6 = rotr32(s6 ^ s11, 12);

    s1 = s1 + s6 + m[11];
    s12 = rotr32(s12 ^ s1, 8);
    s11 = s11 + s12;
    s6 = rotr32(s6 ^ s11, 7);

    s2 = s2 + s7 + m[12];
    s13 = rotr32(s13 ^ s2, 16);
    s8 = s8 + s13;
    s7 = rotr32(s7 ^ s8, 12);

    s2 = s2 + s7 + m[13];
    s13 = rotr32(s13 ^ s2, 8);
    s8 = s8 + s13;
    s7 = rotr32(s7 ^ s8, 7);

    s3 = s3 + s4 + m[14];
    s14 = rotr32(s14 ^ s3, 16);
    s9 = s9 + s14;
    s4 = rotr32(s4 ^ s9, 12);

    s3 = s3 + s4 + m[15];
    s14 = rotr32(s14 ^ s3, 8);
    s9 = s9 + s14;
    s4 = rotr32(s4 ^ s9, 7);

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
void blake32_optimized_permute(uint32_t m[16]) {
    const uint32_t t0  = m[2];
    const uint32_t t1  = m[6];
    const uint32_t t2  = m[3];
    const uint32_t t3  = m[10];
    const uint32_t t4  = m[7];
    const uint32_t t5  = m[0];
    const uint32_t t6  = m[4];
    const uint32_t t7  = m[13];
    const uint32_t t8  = m[1];
    const uint32_t t9  = m[11];
    const uint32_t t10 = m[12];
    const uint32_t t11 = m[5];
    const uint32_t t12 = m[9];
    const uint32_t t13 = m[14];
    const uint32_t t14 = m[15];
    const uint32_t t15 = m[8];

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
 * Splices together 8‐element key and nonce arrays of uint32_t by exchanging
 * their upper and lower 16‐bit halves. Produces a 16‐element output array.
 */
void blake32_optimized_compute_knc(
        const uint32_t key[8],
        const uint32_t nonce[8],
        uint32_t out[16]
) {
    const uint32_t mask1 = 0x0000FFFF;
    const uint32_t mask2 = 0xFFFF0000;

    uint32_t k_val;
    uint32_t n_val;

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
void blake32_optimized_digest_context(
        uint32_t state[16],
        const uint32_t key[8],
        uint32_t context[8]
) {
    blake32_init_state_vector(state, key, 0, KDFDomain_CTX);

    // Round 1
    blake32_optimized_mix_state(state, context);
    blake32_optimized_permute(context);

    // Round 2
    blake32_optimized_mix_state(state, context);
    blake32_optimized_permute(context);

    // Round 3
    blake32_optimized_mix_state(state, context);
    blake32_optimized_permute(context);

    // Round 4
    blake32_optimized_mix_state(state, context);
    blake32_optimized_permute(context);

    // Round 5
    blake32_optimized_mix_state(state, context);
    blake32_optimized_permute(context);

    // Round 6
    blake32_optimized_mix_state(state, context);
    blake32_optimized_permute(context);

    // Round 7
    blake32_optimized_mix_state(state, context);
    blake32_optimized_permute(context);

    // Round 8
    blake32_optimized_mix_state(state, context);
    blake32_optimized_permute(context);

    // Round 9
    blake32_optimized_mix_state(state, context);
    blake32_optimized_permute(context);

    // Round 10
    blake32_optimized_mix_state(state, context);
}


/*
 * derive_keys32 helper: Generates `key_count` 128‐bit round keys.
 *   - entropy[8]:     eight 32‐bit words
 *   - knc[16]:        precomputed key+nonce composite
 *   - key_count:      number of round keys to output
 *   - block_counter:  64‐bit counter for init_state_vector32
 *   - domain:         KDFDomain for domain separation
 *   - out_keys[][16]: output buffer for 128‐bit keys
 */
static void compute_round_keys(
        const uint32_t entropy[8],
        const uint32_t knc[16],
        const uint8_t key_count,
        const uint64_t block_counter,
        const KDFDomain domain,
        uint8_t out_keys[][16]
) {
    uint32_t state_buf[16];
    uint32_t knc_local[16];

    // 1) Copy master knc[] into the local buffer
    for (int i = 0; i < 16; i++) {
        knc_local[i] = knc[i];
    }

    // 2) Initialize BLAKE state from this entropy, counter, and domain
    blake32_init_state_vector(state_buf, entropy, block_counter, domain);

    // 3) For each round, mix and extract a 128‐bit key
    for (size_t round = 0; round < key_count; round++) {

        // a) Mix key+nonce composite into the state
        blake32_optimized_mix_state(state_buf, knc_local);

        // b) Extract state_buf[4..7] → out_keys[round][0..15]
        for (int w = 0; w < 4; w++) {
            const uint32_t v = state_buf[4 + w];
            out_keys[round][4*w + 0] = (uint8_t)(v >> 24);
            out_keys[round][4*w + 1] = (uint8_t)(v >> 16);
            out_keys[round][4*w + 2] = (uint8_t)(v >>  8);
            out_keys[round][4*w + 3] = (uint8_t)(v      );
        }

        // c) Permute knc_local for the next round (unless this was the last round)
        if (round + 1 < key_count) {
            blake32_optimized_permute(knc_local);
        }
    }
}


/**
 * derive_keys32:
 *   - init_state[16]:  precomputed 16‐word BLAKE state
 *   - knc[16]:         precomputed key+nonce composite
 *   - key_count:       number of 128‐bit keys per stream
 *   - block_counter:   64‐bit counter for init_state_vector32
 *   - domain:          KDFDomain for domain separation
 *   - out_keys1[][16]: output buffer for stream #1
 *   - out_keys2[][16]: output buffer for stream #2
 */
void blake32_optimized_derive_keys(
        const uint32_t init_state[16],
        const uint32_t knc[16],
        const uint8_t key_count,
        const uint64_t block_counter,
        const KDFDomain domain,
        uint8_t out_keys1[][16],
        uint8_t out_keys2[][16]
) {
    // 1) Build two 8‐word entropy arrays from init_state
    uint32_t entropy1[8], entropy2[8];
    for (int i = 0; i < 4; i++) {
        entropy1[i]      = init_state[i];
        entropy2[i]      = init_state[4 + i];
        entropy1[4 + i]  = init_state[8 + i];
        entropy2[4 + i]  = init_state[12 + i];
    }

    // 2) Derive stream #1 keys from entropy1
    compute_round_keys(
        entropy1,
        knc,
        key_count,
        block_counter,
        domain,
        out_keys1
    );

    // 3) Derive stream #2 keys from entropy2
    compute_round_keys(
        entropy2,
        knc,
        key_count,
        block_counter,
        domain,
        out_keys2
    );
}
