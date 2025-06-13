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

#ifndef BLAKE32_H
#define BLAKE32_H

#include "blake_shared.h"

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    void g_mix32(
        uint32_t state[16],
        uint8_t a,
        uint8_t b,
        uint8_t c,
        uint8_t d,
        uint32_t mx,
        uint32_t my
    );

    void mix_into_state32(uint32_t state[16], uint32_t m[16]);

    void permute32(uint32_t m[16]);

    void clean_compute_knc32(
        const uint32_t key[8],
        const uint32_t nonce[8],
        uint32_t out[16]
    );

    void clean_digest_context32(
        uint32_t state[16],
        const uint32_t key[8],
        uint32_t context[8]
    );

    void clean_derive_keys32(
        const uint32_t init_state[16],
        const uint32_t knc[16],
        uint8_t        key_count,
        uint64_t       block_counter,
        KDFDomain      domain,
        uint8_t        out_keys1[][16],
        uint8_t        out_keys2[][16]
    );


#ifdef __cplusplus
}
#endif

#endif // BLAKE32_H
