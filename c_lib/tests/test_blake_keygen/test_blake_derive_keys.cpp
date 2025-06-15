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
#include "blake_keygen.h"
#include "helpers/helpers.h"


TEST_CASE("Blake32 clean derive_keys matches Python test vectors", "[unittest][keygen]") {
    run_blake32_derive_keys_test(
        blake32_clean_compute_knc,
        blake32_clean_digest_context,
        blake32_clean_derive_keys
    );
}


TEST_CASE("Blake64 clean derive_keys matches Python test vectors", "[unittest][keygen]") {
    run_blake64_derive_keys_test(
        blake64_clean_compute_knc,
        blake64_clean_digest_context,
        blake64_clean_derive_keys
    );
}


TEST_CASE("Blake32 optimized derive_keys matches Python test vectors", "[unittest][keygen]") {
    run_blake32_derive_keys_test(
        blake32_optimized_compute_knc,
        blake32_optimized_digest_context,
        blake32_optimized_derive_keys
    );
}


TEST_CASE("Blake64 optimized derive_keys matches Python test vectors", "[unittest][keygen]") {
    run_blake64_derive_keys_test(
        blake64_optimized_compute_knc,
        blake64_optimized_digest_context,
        blake64_optimized_derive_keys
    );
}