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

#ifndef BLAKE_KEYGEN_H
#define BLAKE_KEYGEN_H

#include "blake_types.h"

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    /* --- Clean 32-bit Blake --- */
    void blake32_clean_compute_knc(
        const uint32_t key[8],
        const uint32_t nonce[8],
        uint32_t out[16]
    );

    void blake32_clean_digest_context(
        uint32_t state[16],
        const uint32_t key[8],
        uint32_t context[8]
    );

    void blake32_clean_derive_keys(
        const uint32_t init_state[16],
        const uint32_t knc[16],
        uint8_t key_count,
        uint64_t  block_counter,
        KDFDomain domain,
        uint8_t out_keys1[][16],
        uint8_t out_keys2[][16]
    );


    /* --- Optimized 32-bit Blake --- */
    void blake32_optimized_compute_knc(
        const uint32_t key[8],
        const uint32_t nonce[8],
        uint32_t out[16]
    );

    void blake32_optimized_digest_context(
        uint32_t state[16],
        const uint32_t key[8],
        uint32_t context[8]
    );

    void blake32_optimized_derive_keys(
        const uint32_t init_state[16],
        const uint32_t knc[16],
        uint8_t key_count,
        uint64_t block_counter,
        KDFDomain domain,
        uint8_t out_keys1[][16],
        uint8_t out_keys2[][16]
    );


    /* --- Clean 64-bit Blake --- */
    void blake64_clean_compute_knc(
        const uint64_t key[8],
        const uint64_t nonce[8],
        uint64_t out[16]
    );

    void blake64_clean_digest_context(
        uint64_t state[16],
        const uint64_t key[8],
        uint64_t context[8]
    );

    void blake64_clean_derive_keys(
        const uint64_t init_state[16],
        const uint64_t knc[16],
        uint8_t key_count,
        uint64_t block_counter,
        KDFDomain domain,
        uint8_t out_keys1[][16],
        uint8_t out_keys2[][16],
        uint8_t out_keys3[][16],
        uint8_t out_keys4[][16]
    );


    /* --- Optimized 64-bit Blake --- */
    void blake64_optimized_compute_knc(
        const uint64_t key[8],
        const uint64_t nonce[8],
        uint64_t out[16]
    );

    void blake64_optimized_digest_context(
        uint64_t state[16],
        const uint64_t key[8],
        uint64_t context[8]
    );

    void blake64_optimized_derive_keys(
        const uint64_t init_state[16],
        const uint64_t knc[16],
        uint8_t key_count,
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

#endif //BLAKE_KEYGEN_H
