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
#include "../aes_block/helpers.h"
#include "clean_aes.h"
#include "ttable_aes.h"
#include "shared.h"


// Helper function to benchmark AES cipher functions with 1KB of data
inline void benchmark_aes_1kb(const char* benchmark_name, const AesFunc cipher_func) {
    // 1KB = 1024 bytes = 64 blocks of 16 bytes each
    constexpr size_t total_blocks = 64;
    constexpr size_t data_size = total_blocks * 16;

    // Prepare data and keys
    std::vector<uint8_t> data(data_size);
    std::vector<uint8_t> round_keys(total_blocks * 11 * 16); // 11 round keys per block

    // Generate random data and keys
    generate_random_data(data.data(), data_size);
    generate_random_data(round_keys.data(), round_keys.size());

    // Configure AES parameters
    constexpr uint8_t key_count = 11;  // AES-128 uses 11 round keys
    constexpr uint8_t block_count = total_blocks;

    BENCHMARK(benchmark_name) {
        for (uint8_t block_index = 0; block_index < block_count; ++block_index) {
            cipher_func(
                data.data(),
                reinterpret_cast<uint8_t (*)[16]>(round_keys.data()),
                key_count,
                block_count,
                block_index,
                noop_callback
            );
        }
        return data[0]; // Return something to prevent optimization
    };
}


TEST_CASE("Benchmark AES implementations with 1KB data", "[benchmark][aes]") {
    benchmark_aes_1kb("Clean AES Encrypt 1KB", clean_aes_encrypt);
    benchmark_aes_1kb("Clean AES Decrypt 1KB", clean_aes_decrypt);
    benchmark_aes_1kb("T-table AES Encrypt 1KB", ttable_aes_encrypt);
    benchmark_aes_1kb("T-table AES Decrypt 1KB", ttable_aes_decrypt);
}
