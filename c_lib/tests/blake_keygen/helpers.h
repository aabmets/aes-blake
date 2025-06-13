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

#ifndef BLAKE_KEYGEN_HELPERS_H
#define BLAKE_KEYGEN_HELPERS_H

#include <catch2/catch_all.hpp>
#include <cstdint>
#include "blake_shared.h"

using KncFunc32 = void (*)(
    const uint32_t key[8],
    const uint32_t nonce[8],
    uint32_t out[16]
);

using KncFunc64 = void (*)(
    const uint64_t key[8],
    const uint64_t nonce[8],
    uint64_t out[16]
);

using DigestFunc32 = void (*)(
    uint32_t state[16],
    const uint32_t key[8],
    uint32_t context[8]
);

using DigestFunc64 = void (*)(
    uint64_t state[16],
    const uint64_t key[8],
    uint64_t context[8]
);

using DeriveFunc32 = void (*)(
    const uint32_t init_state[16],
    const uint32_t knc[16],
    uint8_t key_count,
    uint64_t block_counter,
    KDFDomain domain,
    uint8_t out_keys1[][16],
    uint8_t out_keys2[][16]
);

using DeriveFunc64 = void (*)(
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


inline void run_blake32_tests(
        const KncFunc32 knc_fn,
        const DigestFunc32 digest_fn,
        const DeriveFunc32 derive_fn
) {
    // 1) Prepare a zeroed key[8] and zeroed nonce/context[8].
    uint32_t zero_key[8]   = {};
    uint32_t zero_nonce[8] = {};

    // 2) Compute the initial state by “digesting the context” (all-zero key/nonce).
    uint32_t init_state[16] = {};
    digest_fn(init_state, zero_key, zero_nonce);

    // 3) Compute knc[16] via compute_key_nonce_composite32(zero_key, zero_nonce, knc).
    uint32_t knc[16];
    knc_fn(zero_key, zero_nonce, knc);

    // 4) We will derive key_count=10 round‐keys for counters 0, 1, 2 and domains MSG, HDR, CHK.
    constexpr size_t key_count = 10;
    uint8_t out_keys1[key_count][16];
    uint8_t out_keys2[key_count][16];

    // 5) Expected first‐round outputs (Python pytest):
    struct Expected {
        KDFDomain domain;
        uint64_t  counter;
        uint8_t   expected_k1[16];
        uint8_t   expected_k2[16];
    };

    Expected cases[] = {
        {
            KDFDomain_MSG,
            0ULL,
            {  // expected_k1 for (domain=MSG, counter=0)
                0xB3, 0xA6, 0xCD, 0xB0,
                0x1A, 0x95, 0x57, 0x74,
                0x28, 0xE8, 0xE4, 0x87,
                0xE4, 0xEC, 0x45, 0x8E
            },
            {  // expected_k2 for (domain=MSG, counter=0)
                0xA1, 0xB9, 0x28, 0x0A,
                0x25, 0xD5, 0x62, 0xD9,
                0x7B, 0x2C, 0x69, 0x63,
                0x45, 0xDF, 0xEE, 0x7F
            }
        },
        {
            KDFDomain_HDR,
            1ULL,
            {  // expected_k1 for (domain=HDR, counter=1)
                0x39, 0xA3, 0x42, 0x5C,
                0x5C, 0x25, 0x67, 0x1D,
                0xF0, 0x09, 0x32, 0xA6,
                0xC7, 0x0F, 0xF7, 0xE4
            },
            {  // expected_k2 for (domain=HDR, counter=1)
                0xC7, 0x21, 0xD5, 0x05,
                0x34, 0xC2, 0x50, 0xD1,
                0xD8, 0x26, 0x2D, 0x2E,
                0x01, 0xB5, 0xA2, 0x11
            }
        },
        {
            KDFDomain_CHK,
            2ULL,
            {  // expected_k1 for (domain=CHK, counter=2)
                0x47, 0x64, 0xEA, 0xEA,
                0x04, 0x9D, 0x16, 0xCD,
                0x42, 0xE7, 0x39, 0x85,
                0x52, 0x46, 0xF8, 0xB5
            },
            {  // expected_k2 for (domain=CHK, counter=2)
                0x21, 0xE9, 0x52, 0xD6,
                0xF7, 0x9C, 0xE2, 0x12,
                0x62, 0x1A, 0x3D, 0x96,
                0xD6, 0x41, 0x84, 0x6E
            }
        }
    };

    for (const auto& [
            domain,
            counter,
            expected_k1,
            expected_k2
        ] : cases) {

        // 6) Call derive_keys32
        derive_fn(
            init_state,
            knc,
            key_count,
            counter,
            domain,
            out_keys1,
            out_keys2
        );

        // 7) Verify that out_keys1[0] and out_keys2[0]
        //    match the expected arrays for this test case.
        for (int i = 0; i < 16; i++) {
            REQUIRE(out_keys1[0][i] == expected_k1[i]);
            REQUIRE(out_keys2[0][i] == expected_k2[i]);
        }
    }
}


inline void run_blake64_tests(
        const KncFunc64 knc_fn,
        const DigestFunc64 digest_fn,
        const DeriveFunc64 derive_fn
) {
    // 1) Prepare a zeroed key[8] and zeroed nonce/context[8].
    uint64_t zero_key[8]   = {};
    uint64_t zero_nonce[8] = {};

    // 2) Compute the initial state by “digesting the context” (all‐zero key/nonce).
    uint64_t init_state[16] = {};
    digest_fn(init_state, zero_key, zero_nonce);

    // 3) Compute knc[16] via compute_key_nonce_composite64(zero_key, zero_nonce, knc).
    uint64_t knc[16];
    knc_fn(zero_key, zero_nonce, knc);

    // 4) We will derive key_count=10 round‐keys for counters 0, 1, 2 and domains MSG, HDR, CHK.
    constexpr size_t key_count = 10;
    uint8_t out_keys1[key_count][16];
    uint8_t out_keys2[key_count][16];
    uint8_t out_keys3[key_count][16];
    uint8_t out_keys4[key_count][16];

    // 5) Expected first‐round outputs (Python pytest):
    struct Expected {
        KDFDomain domain;
        uint64_t  counter;
        uint8_t   expected_k1[16];
        uint8_t   expected_k2[16];
        uint8_t   expected_k3[16];
        uint8_t   expected_k4[16];
    };

    Expected cases[] = {
        {
            KDFDomain_MSG,
            0ULL,
            {  // expected_k1 for (domain=MSG, counter=0)
                0x00, 0xAA, 0x3C, 0xEE,
                0xB1, 0xB0, 0x6B, 0x31,
                0xA8, 0x96, 0xF5, 0xFC,
                0x99, 0x6F, 0x6A, 0xA8
            },
            {  // expected_k2 for (domain=MSG, counter=0)
                0x2E, 0x9A, 0xB4, 0x00,
                0x84, 0x28, 0xAD, 0x9B,
                0xEE, 0xD4, 0xEC, 0x6F,
                0xB8, 0xBC, 0xF1, 0x4D
            },
            {  // expected_k3 for (domain=MSG, counter=0)
                0xEF, 0x8B, 0x07, 0x15,
                0x1D, 0xFF, 0xCF, 0xF8,
                0x8D, 0xDD, 0x46, 0x7E,
                0x03, 0x34, 0x60, 0x56
            },
            {  // expected_k4 for (domain=MSG, counter=0)
                0x30, 0xE4, 0x06, 0x92,
                0xBE, 0x31, 0x69, 0xFA,
                0x29, 0xF3, 0xB0, 0x3D,
                0x65, 0x9F, 0x2F, 0x60
            }
        },
        {
            KDFDomain_HDR,
            1ULL,
            {  // expected_k1 for (domain=HDR, counter=1)
                0xA7, 0x33, 0x26, 0x81,
                0x2D, 0x13, 0xEA, 0xC9,
                0xED, 0xEF, 0x73, 0xDD,
                0xC6, 0xBF, 0x3B, 0x8F
            },
            {  // expected_k2 for (domain=HDR, counter=1)
                0xA8, 0x4A, 0xC8, 0xDE,
                0xB0, 0x55, 0xBE, 0xA4,
                0xD3, 0x2D, 0x62, 0x65,
                0x39, 0x2F, 0xC5, 0x63
            },
            {  // expected_k3 for (domain=HDR, counter=1)
                0x2E, 0xA7, 0xFF, 0x38,
                0x7A, 0x06, 0x29, 0x9A,
                0x0B, 0xDF, 0xE9, 0x50,
                0xA6, 0xCD, 0xB0, 0x96
            },
            {  // expected_k4 for (domain=HDR, counter=1)
                0xFF, 0x6A, 0x7D, 0x2D,
                0x84, 0xCD, 0xB4, 0x9C,
                0x9F, 0x8B, 0xA6, 0x0C,
                0xCA, 0x83, 0x1A, 0xEA
            }
        },
        {
            KDFDomain_CHK,
            2ULL,
            {  // expected_k1 for (domain=CHK, counter=2)
                0xFF, 0x70, 0xF1, 0x92,
                0xE7, 0xBD, 0x58, 0x85,
                0x37, 0x23, 0xA7, 0x3B,
                0xBA, 0x6D, 0x55, 0xE6
            },
            {  // expected_k2 for (domain=CHK, counter=2)
                0xFE, 0xC0, 0xAA, 0x27,
                0x03, 0xBA, 0x02, 0x63,
                0xD3, 0x07, 0x58, 0x90,
                0x8E, 0x6F, 0xB6, 0x2C
            },
            {  // expected_k3 for (domain=CHK, counter=2)
                0x93, 0x42, 0xC4, 0x88,
                0xB6, 0x5D, 0xD3, 0x9D,
                0xE8, 0x16, 0xB6, 0x0B,
                0x84, 0xF1, 0xC7, 0x1E
            },
            {  // expected_k4 for (domain=CHK, counter=2)
                0x24, 0xB8, 0xBC, 0x9C,
                0x08, 0x2F, 0x0B, 0xBE,
                0x0B, 0xA9, 0x66, 0x6A,
                0xC5, 0xC4, 0xB8, 0x87
            }
        }
    };

    for (const auto& [
            domain,
            counter,
            expected_k1,
            expected_k2,
            expected_k3,
            expected_k4
        ] : cases) {

        // 6) Call derive_keys64
        derive_fn(
            init_state,
            knc,
            key_count,
            counter,
            domain,
            out_keys1,
            out_keys2,
            out_keys3,
            out_keys4
        );

        // 7) Verify that out_keys1[0], out_keys2[0], out_keys3[0] and out_keys4[0]
        //    match the expected arrays for this test case.
        for (int i = 0; i < 16; i++) {
            REQUIRE(out_keys1[0][i] == expected_k1[i]);
            REQUIRE(out_keys2[0][i] == expected_k2[i]);
            REQUIRE(out_keys3[0][i] == expected_k3[i]);
            REQUIRE(out_keys4[0][i] == expected_k4[i]);
        }
    }
}

#endif // BLAKE_KEYGEN_HELPERS_H
