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
#include "../blake_keygen/helpers.h"
#include "clean_blake32.h"
#include "clean_blake64.h"
#include "opt_blake32.h"
#include "opt_blake64.h"


/*
 * Benchmarks keygen for encrypting 1KB of data with AES (64 AES blocks).
 * One Blake32 derive_keys call outputs 352 bytes of keys for 2 AES blocks.
 * We generate keys for 64 AES blocks by calling 32bit keygen for 32 times.
 */
static void benchmark_blake32_1kb(
        const KncFunc32 knc_fn,
        const DigestFunc32 digest_fn,
        const DeriveFunc32 derive_fn,
        const char* benchmark_name
) {
    uint32_t zero_key[8]   = {};
    uint32_t zero_nonce[8] = {};

    uint32_t init_state[16] = {};
    digest_fn(init_state, zero_key, zero_nonce);

    uint32_t knc[16];
    knc_fn(zero_key, zero_nonce, knc);

    constexpr size_t key_count = 11;
    uint8_t out_keys1[key_count][16];
    uint8_t out_keys2[key_count][16];

    BENCHMARK(benchmark_name) {
        for (int i = 0; i < 32; ++i) {
            derive_fn(
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


/*
 * Benchmarks keygen for encrypting 1KB of data with AES (64 AES blocks).
 * One Blake64 derive_keys call outputs 704 bytes of keys for 4 AES blocks.
 * We generate keys for 64 AES blocks by calling 64bit keygen for 16 times.
 */
static void benchmark_blake64_1kb(
        const KncFunc64 knc_fn,
        const DigestFunc64 digest_fn,
        const DeriveFunc64 derive_fn,
        const char* benchmark_name
) {
    uint64_t zero_key[8]   = {};
    uint64_t zero_nonce[8] = {};

    uint64_t init_state[16] = {};
    digest_fn(init_state, zero_key, zero_nonce);

    uint64_t knc[16];
    knc_fn(zero_key, zero_nonce, knc);

    constexpr size_t key_count = 11;
    uint8_t out_keys1[key_count][16];
    uint8_t out_keys2[key_count][16];
    uint8_t out_keys3[key_count][16];
    uint8_t out_keys4[key_count][16];

    BENCHMARK(benchmark_name) {
        for (int i = 0; i < 16; ++i) {
            derive_fn(
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
    benchmark_blake32_1kb(
        clean_compute_knc32,
        clean_digest_context32,
        clean_derive_keys32,
        "Clean Blake32 Keygen 1KB"
    );
    benchmark_blake64_1kb(
        clean_compute_knc64,
        clean_digest_context64,
        clean_derive_keys64,
        "Clean Blake64 Keygen 1KB"
    );
    benchmark_blake32_1kb(
        opt_compute_knc32,
        opt_digest_context32,
        opt_derive_keys32,
        "Optimized Blake32 Keygen 1KB"
    );
    benchmark_blake64_1kb(
        opt_compute_knc64,
        opt_digest_context64,
        opt_derive_keys64,
        "Optimized Blake64 Keygen 1KB"
    );
}
