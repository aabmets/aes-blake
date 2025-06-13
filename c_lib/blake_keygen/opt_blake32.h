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

#ifndef OPT_BLAKE32_H
#define OPT_BLAKE32_H

#include "blake_shared.h"

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    void opt_compute_knc32(const uint32_t key[8], const uint32_t nonce[8], uint32_t out[16]);

    void opt_digest_context32(uint32_t state[16], const uint32_t key[8], uint32_t context[8]);

    void opt_derive_keys32(
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

#endif // OPT_BLAKE32_H
