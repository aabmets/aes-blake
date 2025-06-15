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

#ifndef AES_TYPES_H
#define AES_TYPES_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    typedef void (*AES_YieldCallback)(
        uint8_t data[],
        const uint8_t round_keys[][16],
        uint8_t key_count,
        uint8_t block_count,
        uint8_t block_index
    );

    typedef void (*AES_Func)(
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

#endif //AES_TYPES_H
