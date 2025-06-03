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

#ifndef CROSS_PLATFORM_CSPRNG_H
#define CROSS_PLATFORM_CSPRNG_H


#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif


    void csprng_open(void);

    uint8_t csprng_read(void);

    void csprng_close(void);


#ifdef __cplusplus
}
#endif

#endif // CROSS_PLATFORM_CSPRNG_H