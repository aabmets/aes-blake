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
#include "clean_blake32.h"
#include "clean_blake64.h"
#include "opt_blake32.h"
#include "opt_blake64.h"
#include "helpers.h"


TEST_CASE("Clean derive_keys32 matches Python test vectors", "[unittest][keygen]") {
    run_blake32_tests(
        clean_compute_knc32,
        clean_digest_context32,
        clean_derive_keys32
    );
}


TEST_CASE("Clean derive_keys64 matches Python test vectors", "[unittest][keygen]") {
    run_blake64_tests(
        clean_compute_knc64,
        clean_digest_context64,
        clean_derive_keys64
    );
}


TEST_CASE("Optimized derive_keys32 matches Python test vectors", "[unittest][keygen]") {
    run_blake32_tests(
        opt_compute_knc32,
        opt_digest_context32,
        opt_derive_keys32
    );
}


TEST_CASE("Optimized derive_keys64 matches Python test vectors", "[unittest][keygen]") {
    run_blake64_tests(
        opt_compute_knc64,
        opt_digest_context64,
        opt_derive_keys64
    );
}