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

#ifndef BLAKE_TYPES_H
#define BLAKE_TYPES_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    typedef enum {
        KDFDomain_CTX = 0,
        KDFDomain_MSG = 1,
        KDFDomain_HDR = 2,
        KDFDomain_CHK = 3
    } KDFDomain;

    typedef void (*GmixFunc32)(
        uint32_t state[16],
        uint8_t a,
        uint8_t b,
        uint8_t c,
        uint8_t d,
        uint32_t mx,
        uint32_t my
    );

    typedef void (*GmixFunc64)(
        uint64_t state[16],
        uint8_t a,
        uint8_t b,
        uint8_t c,
        uint8_t d,
        uint64_t mx,
        uint64_t my
    );

    typedef void (*MixStateFunc32)(
        uint32_t state[16],
        const uint32_t m[16]
    );

    typedef void (*MixStateFunc64)(
        uint64_t state[16],
        const uint64_t m[16]
    );

    typedef void (*PermuteFunc32)(
        uint32_t m[16]
    );

    typedef void (*PermuteFunc64)(
        uint64_t m[16]
    );

    typedef void (*KncFunc32)(
        const uint32_t key[8],
        const uint32_t nonce[8],
        uint32_t out[16]
    );

    typedef void (*KncFunc64)(
        const uint64_t key[8],
        const uint64_t nonce[8],
        uint64_t out[16]
    );

    typedef void (*DigestFunc32)(
        uint32_t state[16],
        const uint32_t key[8],
        uint32_t context[8]
    );

    typedef void (*DigestFunc64)(
        uint64_t state[16],
        const uint64_t key[8],
        uint64_t context[8]
    );

    typedef void (*DeriveFunc32)(
        const uint32_t init_state[16],
        const uint32_t knc[16],
        uint8_t key_count,
        uint64_t block_counter,
        KDFDomain domain,
        uint8_t out_keys1[][16],
        uint8_t out_keys2[][16]
    );

    typedef void (*DeriveFunc64)(
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

#endif //BLAKE_TYPES_H
