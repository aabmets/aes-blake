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

#ifndef AES_OPS_H
#define AES_OPS_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

    #define XTIME(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1B))

    void add_round_key(uint8_t state[16], const uint8_t round_keys[][16], uint8_t round);

    void shift_rows(uint8_t state[16]);

    void inv_shift_rows(uint8_t state[16]);

    void sub_bytes(uint8_t state[16]);

    void inv_sub_bytes(uint8_t state[16]);


#ifdef __cplusplus
}
#endif

#endif //AES_OPS_H
