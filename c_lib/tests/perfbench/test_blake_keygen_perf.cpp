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
#include <random>
#include "clean_blake32.h"
#include "clean_blake64.h"


// Helper function to set up 1KB worth of key generation for BLAKE32
static void benchmark_blake32_1kb() {
    uint32_t zero_key[8]   = {};
    uint32_t zero_nonce[8] = {};

    uint32_t init_state[16] = {};
    digest_context32(init_state, zero_key, zero_nonce);

    uint32_t knc[16];
    compute_key_nonce_composite32(zero_key, zero_nonce, knc);

    constexpr size_t key_count = 10;
    uint8_t out_keys1[key_count][16];
    uint8_t out_keys2[key_count][16];

    BENCHMARK("BLAKE32 Generate 1KB Keys") {
        for (int i = 0; i < 64; ++i) {
            derive_keys32(
                init_state,
                knc,
                key_count,
                i,  // block_counter
                KDFDomain_MSG,
                out_keys1,
                out_keys2
            );
        }
        return out_keys1[0][0]; // Prevent optimization
    };
}


// Helper function to set up 1KB worth of key generation for BLAKE64
static void benchmark_blake64_1kb() {
    uint64_t zero_key[8]   = {};
    uint64_t zero_nonce[8] = {};

    uint64_t init_state[16] = {};
    digest_context64(init_state, zero_key, zero_nonce);

    uint64_t knc[16];
    compute_key_nonce_composite64(zero_key, zero_nonce, knc);

    constexpr size_t key_count = 10;
    uint8_t out_keys1[key_count][16];
    uint8_t out_keys2[key_count][16];
    uint8_t out_keys3[key_count][16];
    uint8_t out_keys4[key_count][16];

    BENCHMARK("BLAKE64 Generate 1KB Keys") {
        for (int i = 0; i < 64; ++i) {
            derive_keys64(
                init_state,
                knc,
                key_count,
                i,  // block_counter
                KDFDomain_MSG,
                out_keys1,
                out_keys2,
                out_keys3,
                out_keys4
            );
        }
        return out_keys1[0][0]; // Prevent optimization
    };
}


TEST_CASE("Benchmark BLAKE key generation (1KB)", "[benchmark][keygen]") {
    benchmark_blake32_1kb();
    benchmark_blake64_1kb();
}
