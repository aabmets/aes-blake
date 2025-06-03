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
#include "blake_keygen.h"


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

uint32_t get_domain_mask32(const KDFDomain domain) {
    switch (domain) {
        case KDFDomain_CTX: return 0x00000000u;
        case KDFDomain_MSG: return 0x00F0000Fu;
        case KDFDomain_HDR: return 0x0F000F00u;
        case KDFDomain_CHK: return 0xF00F0000u;
        default:            return 0x00000000u;
    }
}

uint64_t get_domain_mask64(const KDFDomain domain) {
    switch (domain) {
        case KDFDomain_CTX: return 0x0000000000000000ULL;
        case KDFDomain_MSG: return 0x0000FF00000000FFULL;
        case KDFDomain_HDR: return 0x00FF000000FF0000ULL;
        case KDFDomain_CHK: return 0xFF0000FF00000000ULL;
        default:            return 0x0000000000000000ULL;
    }
}
