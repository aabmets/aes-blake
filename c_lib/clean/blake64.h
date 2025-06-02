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

#ifndef BLAKE64_H
#define BLAKE64_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t rotr64(uint64_t x, unsigned int r);
void permute64(uint64_t m[16]);

#ifdef __cplusplus
}
#endif

#endif // BLAKE64_H
