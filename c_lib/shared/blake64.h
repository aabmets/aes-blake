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

#ifndef BLAKE64_H
#define BLAKE64_H

#include "blake_keygen.h"

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    uint64_t rotr64(uint64_t x, unsigned int r);

    void g_mix64(uint64_t state[16], int a, int b, int c, int d, uint64_t mx, uint64_t my);

    void mix_into_state64(uint64_t state[16], uint64_t m[16]);

    void permute64(uint64_t m[16]);

    void sub_bytes64(uint64_t state[16]);

    void compute_key_nonce_composite64(uint64_t key[8], uint64_t nonce[8], uint64_t out[16]);

    void init_state_vector64(uint64_t state[16], const uint64_t entropy[8], uint64_t counter, KDFDomain domain);

    void digest_context64(uint64_t state[16], const uint64_t key[8], uint64_t context[8]);

    void derive_keys64(
        const uint64_t init_state[16],
        const uint64_t knc[16],
        size_t key_count,
        uint64_t block_counter,
        KDFDomain domain,
        uint8_t out_keys1[][16],
        uint8_t out_keys2[][16],
        uint8_t out_keys3[][16],
        uint8_t out_keys4[][16]
    );


#ifdef __cplusplus
}
#endif

#endif // BLAKE64_H
