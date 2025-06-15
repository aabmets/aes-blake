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


#ifndef BLAKE_SHARED_H
#define BLAKE_SHARED_H

#include <limits.h>
#include "blake_types.h"

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    extern const uint32_t IV32[8];
    extern const uint64_t IV64[8];

    inline uint32_t blake32_get_domain_mask(const KDFDomain domain) {
        switch (domain) {
            case KDFDomain_CTX: return 0x00000000u;
            case KDFDomain_MSG: return 0x00F0000Fu;
            case KDFDomain_HDR: return 0x0F000F00u;
            case KDFDomain_CHK: return 0xF00F0000u;
            default:            return 0x00000000u;
        }
    }

    inline uint64_t blake64_get_domain_mask(const KDFDomain domain) {
        switch (domain) {
            case KDFDomain_CTX: return 0x0000000000000000ULL;
            case KDFDomain_MSG: return 0x0000FF00000000FFULL;
            case KDFDomain_HDR: return 0x00FF000000FF0000ULL;
            case KDFDomain_CHK: return 0xFF0000FF00000000ULL;
            default:            return 0x0000000000000000ULL;
        }
    }

    inline uint32_t rotr32(const uint32_t x, const uint8_t r) {
        return x >> r | x << (CHAR_BIT * sizeof(uint32_t) - r);
    }

    inline uint64_t rotr64(const uint64_t x, const uint8_t r) {
        return x >> r | x << (CHAR_BIT * sizeof(uint64_t) - r);
    }

    void blake32_init_state_vector(
        uint32_t state[16],
        const uint32_t entropy[8],
        uint64_t counter,
        KDFDomain domain
    );

    void blake64_init_state_vector(
        uint64_t state[16],
        const uint64_t entropy[8],
        uint64_t counter,
        KDFDomain domain
    );


#ifdef __cplusplus
}
#endif

#endif //BLAKE_SHARED_H
