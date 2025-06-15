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
#include "blake_internals.h"
#include "blake_keygen.h"
#include "helpers/helpers.h"


TEST_CASE("Blake32 permute matches Python test vectors", "[unittest][keygen]") {
    run_blake32_permutation_test(blake32_clean_permute);
    run_blake32_permutation_test(blake32_optimized_permute);
}
TEST_CASE("Blake64 permute matches Python test vectors", "[unittest][keygen]") {
    run_blake64_permutation_test(blake64_clean_permute);
    run_blake64_permutation_test(blake64_optimized_permute);
}


TEST_CASE("Blake32 gmix matches Python test vectors", "[unittest][keygen]") {
    run_blake32_gmix_test(blake32_clean_gmix);
}
TEST_CASE("Blake64 gmix matches Python test vectors", "[unittest][keygen]") {
    run_blake64_gmix_test(blake64_clean_gmix);
}


TEST_CASE("Blake32 mix_state matches Python test vectors", "[unittest][keygen]") {
    run_blake32_mix_state_test(blake32_clean_mix_state);
    run_blake32_mix_state_test(blake32_optimized_mix_state);
}
TEST_CASE("Blake64 mix_state matches Python test vectors", "[unittest][keygen]") {
    run_blake64_mix_state_test(blake64_clean_mix_state);
    run_blake64_mix_state_test(blake64_optimized_mix_state);
}


TEST_CASE("Blake32 compute_knc matches Python test vectors", "[unittest][keygen]") {
    run_blake32_compute_knc_test(blake32_clean_compute_knc);
    run_blake32_compute_knc_test(blake32_optimized_compute_knc);
}
TEST_CASE("Blake64 compute_knc matches Python test vectors", "[unittest][keygen]") {
    run_blake64_compute_knc_test(blake64_clean_compute_knc);
    run_blake64_compute_knc_test(blake64_optimized_compute_knc);
}


TEST_CASE("Blake32 digest_context matches Python test vectors", "[unittest][keygen]") {
    run_blake32_compute_knc_test(blake32_clean_compute_knc);
    run_blake32_compute_knc_test(blake32_optimized_compute_knc);
}
TEST_CASE("Blake64 digest_context matches Python test vectors", "[unittest][keygen]") {
    run_blake64_digest_context_test(blake64_clean_digest_context);
    run_blake64_digest_context_test(blake64_optimized_digest_context);
}