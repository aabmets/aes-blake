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
#include <cstring>
#include "aes_block.h"
#include "helpers.h"


TEST_CASE("Clean AES-128 FIPS-197 Vectors", "[unittest][aes]") {
    run_fips197_vectors(aes_encrypt_clean, aes_decrypt_clean);
}


TEST_CASE("Clean AES-128 Two-Block Random Keys", "[unittest][aes]") {
    run_two_block_random_vectors(aes_encrypt_clean, aes_decrypt_clean);
}


TEST_CASE("T-table AES-128 FIPS-197 Vectors", "[unittest][aes]") {
    run_fips197_vectors(aes_encrypt_optimized, aes_decrypt_optimized);
}


TEST_CASE("T-table AES-128 Two-Block Random Keys", "[unittest][aes]") {
    run_two_block_random_vectors(aes_encrypt_optimized, aes_decrypt_optimized);
}
