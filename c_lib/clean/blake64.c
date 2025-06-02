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
 * Rotate a 64-bit word `x` right by `r` bits.
 * Assumes 0 ≤ r < 64. If `r` might be ≥64, you can mask it:
 *     r &= 63;
 */
uint64_t rotr64(const uint64_t x, const unsigned int r) {
    return (x >> r) | (x << (64 - r));
}


/*
 * Performs the BLAKE3 message permutation on the input message vector.
 *
 * The function reorders a list of BaseUint elements according to the
 * fixed BLAKE3 permutation schedule and returns the permuted list.
 *
 * Args:
 *     m (list[BaseUint]): The input message vector to permute.
 *
 * Returns:
 *     list[BaseUint]: The permuted message vector.
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
