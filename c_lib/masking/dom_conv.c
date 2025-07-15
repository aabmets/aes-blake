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

#include <stdint.h>

#include "masking.h"
#include "dom_types.h"
#include "dom_internal_defs.h"


#ifndef DOM_CONV
#define DOM_CONV(BL)                                                            \
                                                                                \
int FN(dom_conv, BL)(MTP(BL) mv, domain_t domain)                               \
{                                                                               \
    int(*conv)(MTP(BL)) = domain == DOMAIN_BOOLEAN                              \
        ? FN(dom_conv_atob, BL)                                                 \
        : FN(dom_conv_btoa, BL);                                                \
                                                                                \
    if (!mv || (mv->domain != domain && conv(mv)))                              \
        return 1;                                                               \
    return 0;                                                                   \
}                                                                               \
                                                                                \
                                                                                \
int FN(dom_conv_many, BL)(MTPA(BL) mvs, uint8_t count, domain_t domain)         \
{                                                                               \
    const uint8_t pair_count = count - 1;                                       \
                                                                                \
    for (uint8_t i = 0; i < pair_count; ++i) {                                  \
        if (mvs[i]->sig != mvs[i+1]->sig) {                                     \
            return 1;                                                           \
        }                                                                       \
    }                                                                           \
                                                                                \
    int(*conv)(MTP(BL)) = domain == DOMAIN_BOOLEAN                              \
        ? FN(dom_conv_atob, BL)                                                 \
        : FN(dom_conv_btoa, BL);                                                \
                                                                                \
    for(uint8_t i = 0; i < count; ++i) {                                        \
        MTP(BL) mv = mvs[i];                                                    \
        if (!mv || (mv->domain != domain && conv(mv))) {                        \
            return 1;                                                           \
        }                                                                       \
    }                                                                           \
    return 0;                                                                   \
}                                                                               \

#endif //DOM_CONV


DOM_CONV(8)
DOM_CONV(16)
DOM_CONV(32)
DOM_CONV(64)
