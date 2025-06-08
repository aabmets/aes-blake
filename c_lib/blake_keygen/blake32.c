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
#include "../aes_block/aes_sbox.h"
#include "blake_const.h"


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


/*
 * Initializes the 16-word state matrix for the compression function.
 * Implements:
 *   state[0..3]   = IV constants (BLAKE2s)
 *   state[4..11]  = entropy[0..7]
 *   state[12..15] = IV constants (BLAKE2s)
 *   then:
 *     add low‐32 bits of counter to state[4..7]
 *     add high‐32 bits of counter to state[8..11]
 *     XOR each of state[12..15] with the domain mask
 */
void init_state_vector32(
    uint32_t state[16], const uint32_t entropy[8],
    const uint64_t counter, const KDFDomain domain
) {
    for (int i = 0; i < 4; i++) {
        state[i] = IV32[i];
    }
    for (int i = 0; i < 8; i++) {
        state[i+4] = entropy[i];
    }
    for (int i = 4; i < 8; i++) {
        state[i+8] = IV32[i];
    }
    const uint32_t ctr_low  = (uint32_t)(counter & 0xFFFFFFFFu);
    const uint32_t ctr_high = (uint32_t)(counter >> 32 & 0xFFFFFFFFu);
    const uint32_t d_mask = get_domain_mask32(domain);

    for (int i = 4; i <= 7; i++) {
        state[i] += ctr_low;
    }
    for (int i = 8; i <= 11; i++) {
        state[i] += ctr_high;
    }
    for (int i = 12; i <= 15; i++) {
        state[i] ^= d_mask;
    }
}


/*
 * Digests the cipher context through ten rounds of compression.
 */
void digest_context32(uint32_t state[16], const uint32_t key[8], uint32_t context[8]) {
    init_state_vector32(state, key, 0, KDFDomain_CTX);
    for (int i = 0; i < 9; i++) {
        mix_into_state32(state, context);
        permute32(context);
    }
    mix_into_state32(state, context);
    sub_bytes32(state);
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
static void compute_round_keys32(
        const uint32_t entropy[8],
        const uint32_t knc[16],
        const size_t key_count,
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
    init_state_vector32(state_buf, entropy, block_counter, domain);

    // 3) For each round, mix and extract a 128‐bit key
    for (size_t round = 0; round < key_count; round++) {

        // a) Mix key+nonce composite into the state
        mix_into_state32(state_buf, knc_local);

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
            permute32(knc_local);
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
void derive_keys32(
        const uint32_t init_state[16],
        const uint32_t knc[16],
        const size_t key_count,
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
    compute_round_keys32(
        entropy1,
        knc,
        key_count,
        block_counter,
        domain,
        out_keys1
    );

    // 3) Derive stream #2 keys from entropy2
    compute_round_keys32(
        entropy2,
        knc,
        key_count,
        block_counter,
        domain,
        out_keys2
    );
}
