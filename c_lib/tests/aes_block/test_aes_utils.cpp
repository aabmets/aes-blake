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
#include "aes_utils.h"


TEST_CASE("Transposed state matrix matches expected value", "[unittest][aes]") {
    const uint8_t initial[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const uint8_t expected[16] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
    uint8_t tmp[16];

    memcpy(tmp, initial, 16);

    transpose_state_matrix(tmp);

    for (int i = 0; i < 16; ++i) {
        REQUIRE(tmp[i] == expected[i]);
    }

    transpose_state_matrix(tmp);

    for (int i = 0; i < 16; ++i) {
        REQUIRE(tmp[i] == initial[i]);
    }
}
