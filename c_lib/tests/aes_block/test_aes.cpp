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
#include "clean_aes.h"
#include "ttable_aes.h"
#include "helpers.h"


TEST_CASE("Clean AES-128 FIPS-197 Vectors", "[aes][clean_aes][fips197]") {
    run_fips197_vectors(clean_aes_encrypt, clean_aes_decrypt);
}


TEST_CASE("Clean AES-128 Two-Block Random Keys", "[aes][clean_aes][two_block]") {
    run_two_block_random_vectors(clean_aes_encrypt, clean_aes_decrypt);
}


TEST_CASE("T-table AES-128 FIPS-197 Vectors", "[aes][ttable_aes][fips197]") {
    run_fips197_vectors(ttable_aes_encrypt, clean_aes_decrypt);
}


TEST_CASE("T-table AES-128 Two-Block Random Keys", "[aes][ttable_aes][two_block]") {
    run_two_block_random_vectors(ttable_aes_encrypt, clean_aes_decrypt);
}
