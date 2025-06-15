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


void run_blake32_derive_keys_test(
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
                0x2C, 0x23, 0xCE, 0x27,
                0xA2, 0xD0, 0x70, 0xBF,
                0xB6, 0x87, 0xF0, 0x6E,
                0x7F, 0x67, 0x09, 0x24,
            },
            {  // expected_k2 for (domain=MSG, counter=0)
                0xBD, 0x5F, 0xA1, 0xB1,
                0x45, 0x57, 0x04, 0x9A,
                0x3B, 0xF9, 0xFD, 0xA4,
                0x3E, 0xEE, 0x4F, 0x5E,
            }
        },
        {
            KDFDomain_HDR,
            1ULL,
            {  // expected_k1 for (domain=HDR, counter=1)
                0xC7, 0x06, 0x08, 0xFD,
                0xE3, 0x51, 0x95, 0x2C,
                0xD5, 0x4C, 0xAF, 0x93,
                0xF1, 0x87, 0x7C, 0x92,
            },
            {  // expected_k2 for (domain=HDR, counter=1)
                0x06, 0x3D, 0xFB, 0x16,
                0x96, 0xD3, 0xAC, 0x49,
                0xD4, 0xF7, 0xED, 0x15,
                0xCF, 0x60, 0xB3, 0xD8,
            }
        },
        {
            KDFDomain_CHK,
            2ULL,
            {  // expected_k1 for (domain=CHK, counter=2)
                0x3A, 0xC7, 0xE0, 0xF4,
                0xD6, 0xAF, 0xA4, 0x6C,
                0x86, 0xEA, 0x34, 0x6D,
                0x3D, 0x75, 0x3D, 0x6B,
            },
            {  // expected_k2 for (domain=CHK, counter=2)
                0x68, 0x6D, 0x15, 0x79,
                0x68, 0x92, 0x3B, 0xBF,
                0xF6, 0xD3, 0x37, 0x32,
                0x13, 0x7F, 0x2C, 0x07,
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
