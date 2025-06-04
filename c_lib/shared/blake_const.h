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

    extern const uint32_t IV32[8];

    extern const uint64_t IV64[8];

    uint32_t get_domain_mask32(KDFDomain domain);

    uint64_t get_domain_mask64(KDFDomain domain);


#ifdef __cplusplus
}
#endif

#endif //BLAKE_KEYGEN_H
