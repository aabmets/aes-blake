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

#ifndef TTABLE_AES_H
#define TTABLE_AES_H

#include "aes_types.h"

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

    void ttable_aes_encrypt(
        uint8_t data[],
        const uint8_t round_keys[][16],
        uint8_t key_count,
        uint8_t block_count,
        uint8_t block_index,
        AES_YieldCallback callback
    );

    void ttable_aes_decrypt(
        uint8_t data[],
        const uint8_t round_keys[][16],
        uint8_t key_count,
        uint8_t block_count,
        uint8_t block_index,
        AES_YieldCallback callback
    );


#ifdef __cplusplus
}
#endif

#endif //TTABLE_AES_H
