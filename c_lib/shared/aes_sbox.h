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

#ifndef AES_SBOX_H
#define AES_SBOX_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

extern uint8_t aes_sbox[];
extern uint8_t aes_inv_sbox[];

#ifdef __cplusplus
}
#endif

#endif // AES_SBOX_H
