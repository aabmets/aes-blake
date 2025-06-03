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

#ifndef BLAKE32_H
#define BLAKE32_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif


uint32_t rotr32(uint32_t x, unsigned int r);

void g_mix32(uint32_t state[16], int a, int b, int c, int d, uint32_t mx, uint32_t my);

void mix_into_state32(uint32_t state[16], uint32_t m[16]);

void permute32(uint32_t m[16]);


#ifdef __cplusplus
}
#endif

#endif // BLAKE32_H
