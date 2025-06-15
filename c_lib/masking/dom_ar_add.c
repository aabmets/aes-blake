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

#include "csprng.h"
#include "masking.h"

// ARITHMETIC ADDITION

void dom_ar_add8(const uint8_t x[N_SHARES], const uint8_t y[N_SHARES], uint8_t out[N_SHARES]) {
    uint8_t carry[N_SHARES];
    dom_mask8(0, carry);

    // Clear output shares
    for (int j = 0; j < N_SHARES; j++) {
        out[j] = 0;
    }

    // Process each bit with a masked full-adder
    for (int i = 0; i < BITS_8; i++) {
        // Extract bit-shares
        uint8_t x_bit[N_SHARES], y_bit[N_SHARES];
        for (int j = 0; j < N_SHARES; j++) {
            x_bit[j] = x[j] >> i & 1;
            y_bit[j] = y[j] >> i & 1;
        }

        // t = x_bit XOR y_bit
        uint8_t t[N_SHARES];
        dom_bw_xor8(x_bit, y_bit, t);

        // sum_bit = t XOR carry
        uint8_t s_bit[N_SHARES];
        dom_bw_xor8(t, carry, s_bit);

        // carry_out = (x_bit & y_bit) XOR (t & carry)
        uint8_t xy[N_SHARES], tc[N_SHARES];
        dom_bw_and8(x_bit, y_bit, xy);
        dom_bw_and8(t, carry, tc);

        uint8_t carry_out[N_SHARES];
        dom_bw_xor8(xy, tc, carry_out);

        // Assemble output bit and update carry
        for (int j = 0; j < N_SHARES; j++) {
            out[j] ^= s_bit[j] << i;
            carry[j] = carry_out[j];
        }
    }

    asm volatile("" ::: "memory");
}


void dom_ar_add32(const uint32_t x[N_SHARES], const uint32_t y[N_SHARES], uint32_t out[N_SHARES]) {
    uint32_t carry[N_SHARES];
    dom_mask32(0, carry);

    // Clear output shares
    for (int j = 0; j < N_SHARES; j++) {
        out[j] = 0;
    }

    // Process each bit with a masked full-adder
    for (int i = 0; i < BITS_32; i++) {
        // Extract bit-shares
        uint32_t x_bit[N_SHARES], y_bit[N_SHARES];
        for (int j = 0; j < N_SHARES; j++) {
            x_bit[j] = (x[j] >> i) & 1;
            y_bit[j] = (y[j] >> i) & 1;
        }

        // t = x_bit XOR y_bit
        uint32_t t[N_SHARES];
        dom_bw_xor32(x_bit, y_bit, t);

        // sum_bit = t XOR carry
        uint32_t s_bit[N_SHARES];
        dom_bw_xor32(t, carry, s_bit);

        // carry_out = (x_bit & y_bit) XOR (t & carry)
        uint32_t xy[N_SHARES], tc[N_SHARES];
        dom_bw_and32(x_bit, y_bit, xy);
        dom_bw_and32(t, carry, tc);

        uint32_t carry_out[N_SHARES];
        dom_bw_xor32(xy, tc, carry_out);

        // Assemble output bit and update carry
        for (int j = 0; j < N_SHARES; j++) {
            out[j] ^= s_bit[j] << i;
            carry[j] = carry_out[j];
        }
    }

    // --- Compiler memory barrier ---
    asm volatile("" ::: "memory");
}


void dom_ar_add64(const uint64_t x[N_SHARES], const uint64_t y[N_SHARES], uint64_t out[N_SHARES]) {
    uint64_t carry[N_SHARES];
    dom_mask64(0, carry);

    // Clear output shares
    for (int j = 0; j < N_SHARES; j++) {
        out[j] = 0;
    }

    // Process each bit with a masked full-adder
    for (int i = 0; i < BITS_64; i++) {
        // Extract bit-shares
        uint64_t x_bit[N_SHARES], y_bit[N_SHARES];
        for (int j = 0; j < N_SHARES; j++) {
            x_bit[j] = (x[j] >> i) & 1;
            y_bit[j] = (y[j] >> i) & 1;
        }

        // t = x_bit XOR y_bit
        uint64_t t[N_SHARES];
        dom_bw_xor64(x_bit, y_bit, t);

        // sum_bit = t XOR carry
        uint64_t s_bit[N_SHARES];
        dom_bw_xor64(t, carry, s_bit);

        // carry_out = (x_bit & y_bit) XOR (t & carry)
        uint64_t xy[N_SHARES], tc[N_SHARES];
        dom_bw_and64(x_bit, y_bit, xy);
        dom_bw_and64(t, carry, tc);

        uint64_t carry_out[N_SHARES];
        dom_bw_xor64(xy, tc, carry_out);

        // Assemble output bit and update carry
        for (int j = 0; j < N_SHARES; j++) {
            out[j] ^= s_bit[j] << i;
            carry[j] = carry_out[j];
        }
    }

    // --- Compiler memory barrier ---
    asm volatile("" ::: "memory");
}
