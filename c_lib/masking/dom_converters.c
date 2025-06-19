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

#include "csprng.h"
#include "dom_types.h"


/*
 *   Parametrized preprocessor macro template for all converter functions.
 */
#ifndef DOM_CONVERTER_FUNCTIONS
#define DOM_CONVERTER_FUNCTIONS(TYPE, FN_SUFFIX)                                \
                                                                                \
void dom_conv_btoa_##FN_SUFFIX(masked_##TYPE* mv) {                             \
    /* working registers */                                                     \
    TYPE z, u, v, w;                                                            \
                                                                                \
    /* boolean shares */                                                        \
    const TYPE xp = mv->shares[0];  /* x prime = x ⊕ r1 ⊕ r2 */                 \
    const TYPE r1 = mv->shares[1];                                              \
    const TYPE r2 = mv->shares[2];                                              \
                                                                                \
    /* fresh randomness */                                                      \
    TYPE rand[5];                                                               \
    csprng_read_array((uint8_t *)rand, sizeof(rand));                           \
                                                                                \
    const TYPE g1 = rand[0];  /* gamma 1 */                                     \
    const TYPE g2 = rand[1];  /* gamma 2 */                                     \
    const TYPE aa = rand[2];  /* alpha  */                                      \
    const TYPE s1 = rand[3];                                                    \
    const TYPE s2 = rand[4];                                                    \
                                                                                \
    /* Hutter & Tunstall 2016 Algorithm 2 */                                    \
    z  = g1 ^ r1;  /*  1 */                                                     \
    z ^= g2;       /*  2 */                                                     \
    z ^= r2;       /*  3 */                                                     \
                                                                                \
    u  = xp ^ z;   /*  4 */                                                     \
    z ^= aa;       /*  5 */                                                     \
    u += z;        /*  6 */                                                     \
                                                                                \
    v  = xp ^ g1;  /*  7 */                                                     \
    v ^= aa;       /*  8 */                                                     \
    v += g1;       /*  9 */                                                     \
                                                                                \
    w  = xp ^ g2;  /* 10 */                                                     \
    w ^= aa;       /* 11 */                                                     \
    w += g2;       /* 12 */                                                     \
                                                                                \
    z  = r2 ^ s1;  /* 13 */                                                     \
    u ^= r2;       /* 14 */                                                     \
    u ^= v;        /* 15 */                                                     \
    u ^= w;        /* 16 */                                                     \
                                                                                \
    v  = u ^ s1;   /* 17 */                                                     \
    v += r2;       /* 18 */                                                     \
    w  = u ^ z;    /* 19 */                                                     \
    v ^= w;        /* 20 */                                                     \
    w  = u + z;    /* 21 */                                                     \
    z  = v ^ w;    /* 22 */                                                     \
                                                                                \
    w  = aa ^ r2;  /* 23 */                                                     \
    u  = s2 ^ r1;  /* 24 */                                                     \
    u -= w;        /* 25 */                                                     \
    w ^= s2;       /* 26 */                                                     \
    v  = w ^ r1;   /* 27 */                                                     \
    w -= r1;       /* 28 */                                                     \
    u ^= v;        /* 29 */                                                     \
    u ^= w;        /* 30 */                                                     \
                                                                                \
    z += u;        /* 31 */                                                     \
                                                                                \
    /* write back */                                                            \
    mv->shares[0] = z;   /* x + s1 + s2 (mod 2^n) */                            \
    mv->shares[1] = s1;                                                         \
    mv->shares[2] = s2;                                                         \
    mv->domain = DOMAIN_ARITHMETIC;                                             \
}                                                                               \
                                                                                \
                                                                                \
void dom_conv_atob_##FN_SUFFIX(masked_##TYPE* mv) {                             \
    /* TODO: replace this naive insecure implementation */                      \
    TYPE unmasked_value = mv->shares[0] - mv->shares[1] - mv->shares[2];        \
    mv->shares[0] = unmasked_value ^ mv->shares[1] ^ mv->shares[2];             \
    mv->domain = DOMAIN_BOOLEAN;                                                \
}                                                                               \

#endif //DOM_CONVERTER_FUNCTIONS


/*
 *   Create converter functions for all supported types.
 */
DOM_CONVERTER_FUNCTIONS(uint8_t, u8)
DOM_CONVERTER_FUNCTIONS(uint32_t, u32)
DOM_CONVERTER_FUNCTIONS(uint64_t, u64)
