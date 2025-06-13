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

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    extern const uint32_t IV32[8];
    extern const uint64_t IV64[8];

    typedef enum {
        KDFDomain_CTX = 0,
        KDFDomain_MSG = 1,
        KDFDomain_HDR = 2,
        KDFDomain_CHK = 3
    } KDFDomain;

    inline uint32_t get_domain_mask32(const KDFDomain domain) {
        switch (domain) {
            case KDFDomain_CTX: return 0x00000000u;
            case KDFDomain_MSG: return 0x00F0000Fu;
            case KDFDomain_HDR: return 0x0F000F00u;
            case KDFDomain_CHK: return 0xF00F0000u;
            default:            return 0x00000000u;
        }
    }

    inline uint64_t get_domain_mask64(const KDFDomain domain) {
        switch (domain) {
            case KDFDomain_CTX: return 0x0000000000000000ULL;
            case KDFDomain_MSG: return 0x0000FF00000000FFULL;
            case KDFDomain_HDR: return 0x00FF000000FF0000ULL;
            case KDFDomain_CHK: return 0xFF0000FF00000000ULL;
            default:            return 0x0000000000000000ULL;
        }
    }

    inline uint32_t rotr32(const uint32_t x, const uint8_t r) {
        return x >> r | x << (32 - r);
    }

    inline uint64_t rotr64(const uint64_t x, const uint8_t r) {
        return x >> r | x << (64 - r);
    }

    void init_state_vector32(
        uint32_t state[16],
        const uint32_t entropy[8],
        uint64_t counter,
        KDFDomain domain
    );

    void init_state_vector64(
        uint64_t state[16],
        const uint64_t entropy[8],
        uint64_t counter,
        KDFDomain domain
    );

    void sub_bytes32(uint32_t state[16]);

    void sub_bytes64(uint64_t state[16]);


#ifdef __cplusplus
}
#endif

#endif //BLAKE_SHARED_H
