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

#include <catch2/catch_all.hpp>
#include "blake_types.h"


void run_blake64_derive_keys_test(
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
                0xFB, 0xE5, 0xF3, 0xC3,
                0xC0, 0xD1, 0x09, 0x26,
                0xCF, 0x49, 0x45, 0xC8,
                0x1C, 0x51, 0x5F, 0x0C,
            },
            {  // expected_k2 for (domain=MSG, counter=0)
                0x3D, 0xAF, 0x00, 0x51,
                0x7F, 0x37, 0xCE, 0x3B,
                0x05, 0x83, 0x6F, 0xDF,
                0x50, 0xBD, 0x37, 0x76,
            },
            {  // expected_k3 for (domain=MSG, counter=0)
                0x6E, 0x2E, 0xE5, 0x47,
                0x98, 0x7F, 0x28, 0x4D,
                0x7E, 0xA2, 0xE5, 0xF2,
                0x6E, 0x3A, 0xC3, 0x58,
            },
            {  // expected_k4 for (domain=MSG, counter=0)
                0x4E, 0x64, 0xEE, 0xA4,
                0x6B, 0x1C, 0xC0, 0xE8,
                0x0E, 0x34, 0x6A, 0xF5,
                0x85, 0x69, 0x26, 0xE6,
            }
        },
        {
            KDFDomain_HDR,
            1ULL,
            {  // expected_k1 for (domain=HDR, counter=1)
                0x97, 0x6A, 0x21, 0x61,
                0xFB, 0x02, 0x0C, 0x84,
                0x4F, 0x8A, 0xE9, 0xBC,
                0xF3, 0xF6, 0x00, 0x6E,
            },
            {  // expected_k2 for (domain=HDR, counter=1)
                0x55, 0x55, 0xBB, 0x9B,
                0xDB, 0xF8, 0x73, 0xF4,
                0xB6, 0x79, 0x54, 0x5C,
                0x28, 0x58, 0x35, 0xC3,
            },
            {  // expected_k3 for (domain=HDR, counter=1)
                0x72, 0xF8, 0x27, 0xBE,
                0x2E, 0x28, 0xE8, 0xBD,
                0x9E, 0xE3, 0x33, 0x4D,
                0x18, 0xEA, 0xC6, 0x28,
            },
            {  // expected_k4 for (domain=HDR, counter=1)
                0xFE, 0x30, 0xDD, 0xCE,
                0x1A, 0xB8, 0x7F, 0x3E,
                0xFF, 0x0D, 0xA7, 0x38,
                0x94, 0xD7, 0x67, 0x1C,
            }
        },
        {
            KDFDomain_CHK,
            2ULL,
            {  // expected_k1 for (domain=CHK, counter=2)
                0xA7, 0x69, 0x6B, 0xE8,
                0x57, 0x12, 0x4B, 0x08,
                0x10, 0xD8, 0xCD, 0x2C,
                0x00, 0x8E, 0xD8, 0xBA,
            },
            {  // expected_k2 for (domain=CHK, counter=2)
                0x9D, 0x2C, 0x55, 0x73,
                0x97, 0x0E, 0xE5, 0xF6,
                0x79, 0xEB, 0x2B, 0xC0,
                0x22, 0x76, 0xD1, 0x18,
            },
            {  // expected_k3 for (domain=CHK, counter=2)
                0xF5, 0x8C, 0x41, 0x02,
                0x20, 0xCA, 0x3A, 0x76,
                0xC4, 0x60, 0xD9, 0x7E,
                0x78, 0xEA, 0xD4, 0x94,
            },
            {  // expected_k4 for (domain=CHK, counter=2)
                0x22, 0x3E, 0x98, 0xC7,
                0x8F, 0x34, 0xF1, 0xCD,
                0x79, 0x97, 0xA0, 0x23,
                0xBA, 0x24, 0x84, 0x6A,
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