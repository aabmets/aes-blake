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

#ifndef AES_TABLES_H
#define AES_TABLES_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    extern const uint32_t Te0[256];
    extern const uint32_t Te1[256];
    extern const uint32_t Te2[256];
    extern const uint32_t Te3[256];


#ifdef __cplusplus
}
#endif

#endif //AES_TABLES_H
