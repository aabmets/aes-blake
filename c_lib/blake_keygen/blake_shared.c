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
#include "blake_types.h"
#include "blake_shared.h"


const uint32_t IV32[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

const uint64_t IV64[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};


/*
 * Initializes the 16-word state matrix for the compression function.
 * Implements:
 *   state[0..3]   = IV constants[0..3] (BLAKE2s)
 *   state[4..7] = entropy[0..3] + low‐32 bits of counter
 *   state[8..11] = entropy[4..7] + high‐32 bits of counter
 *   state[12..15] = IV constants[4..7] (BLAKE2s) ⊕ domain mask
 */
void blake32_init_state_vector(
        uint32_t state[16],
        const uint32_t entropy[8],
        const uint64_t counter,
        const KDFDomain domain
) {
    const uint32_t ctr_low  = (uint32_t)(counter & 0xFFFFFFFFu);
    const uint32_t ctr_high = (uint32_t)(counter >> 32 & 0xFFFFFFFFu);
    const uint32_t d_mask = blake32_get_domain_mask(domain);

    state[0] = IV32[0];
    state[1] = IV32[1];
    state[2] = IV32[2];
    state[3] = IV32[3];

    state[4] = entropy[0] + ctr_low;
    state[5] = entropy[1] + ctr_low;
    state[6] = entropy[2] + ctr_low;
    state[7] = entropy[3] + ctr_low;

    state[8] = entropy[4] + ctr_high;
    state[9] = entropy[5] + ctr_high;
    state[10] = entropy[6] + ctr_high;
    state[11] = entropy[7] + ctr_high;

    state[12] = IV32[4] ^ d_mask;
    state[13] = IV32[5] ^ d_mask;
    state[14] = IV32[6] ^ d_mask;
    state[15] = IV32[7] ^ d_mask;
}


/*
 * Initializes the 16-word state matrix for the compression function.
 * Implements:
 *   state[0..3] = IV constants[0..3] (BLAKE2b)
 *   state[4..7] = entropy[0..3] + low‐32 bits of counter
 *   state[8..11] = entropy[4..7] + high‐32 bits of counter
 *   state[12..15] = IV constants[4..7] (BLAKE2b) ⊕ domain mask
 */
void blake64_init_state_vector(
        uint64_t state[16],
        const uint64_t entropy[8],
        const uint64_t counter,
        const KDFDomain domain
) {
    const uint32_t ctr_low  = (uint32_t)(counter & 0xFFFFFFFFu);
    const uint32_t ctr_high = (uint32_t)(counter >> 32 & 0xFFFFFFFFu);
    const uint64_t d_mask = blake64_get_domain_mask(domain);

    state[0] = IV64[0];
    state[1] = IV64[1];
    state[2] = IV64[2];
    state[3] = IV64[3];

    state[4] = entropy[0] + ctr_low;
    state[5] = entropy[1] + ctr_low;
    state[6] = entropy[2] + ctr_low;
    state[7] = entropy[3] + ctr_low;

    state[8] = entropy[4] + ctr_high;
    state[9] = entropy[5] + ctr_high;
    state[10] = entropy[6] + ctr_high;
    state[11] = entropy[7] + ctr_high;

    state[12] = IV64[4] ^ d_mask;
    state[13] = IV64[5] ^ d_mask;
    state[14] = IV64[6] ^ d_mask;
    state[15] = IV64[7] ^ d_mask;
}
