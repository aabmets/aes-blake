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

#include <stdbool.h>
#include <stdint.h>
#include "ttable_aes.h"
#include "aes_sbox.h"


static uint32_t Te0[256];
static uint32_t Te1[256];
static uint32_t Te2[256];
static uint32_t Te3[256];

static uint32_t Td0[256];
static uint32_t Td1[256];
static uint32_t Td2[256];
static uint32_t Td3[256];

static bool tables_generated = false;
static bool inv_tables_generated = false;


/**
 * Precomputes AES T-tables (Te0–Te3) for fast SubBytes+ShiftRows+MixColumns operations.
 *
 * On its first call, this function fills four 256-entry arrays (Te0, Te1, Te2, Te3)
 * using the AES S-box (aes_sbox[]) and the GF(2^8) “xtime” operation. Each table entry
 * encodes SubBytes, ShiftRows, and MixColumns combined into a single little-endian
 * 32-bit word so that, at runtime, t-table lookups can be indexed directly by state
 * bytes with no additional shifts or byte-swapping. Once all 256 entries per table
 * are computed, the static flag `tables_generated` is set to true to skip reinitialization
 * on later calls.
 *
 * Details:
 *   • Uses aes_sbox[i] to get S-box byte s.
 *   • Computes s2 = xtime(s) (i.e., multiplication by 2 in GF(2^8)) and s3 = s2 ^ s.
 *   • Populates Te0, Te1, Te2, and Te3 tables so that, for example, indexing Te0[b]
 *     yields a 32-bit little-endian word whose bytes correspond to MixColumns(SubBytes(
 *     ShiftRows-input)) for column 0, when b is the “row-0” byte of that column.
 *   • After filling all entries, sets `tables_generated = true` so future calls return
 *     immediately.
 */
static void generate_tables(void) {
    for (int i = 0; i < 256; i++) {
        uint8_t s = aes_sbox[i];
        uint8_t s2 = (uint8_t)(s << 1) ^ (uint8_t)((s >> 7) * 0x1B);
        uint8_t s3 = (uint8_t)(s2 ^ s);

        Te0[i] = (uint32_t)s3 << 24
               | (uint32_t)s  << 16
               | (uint32_t)s  << 8
               | (uint32_t)s2;

        Te1[i] = (uint32_t)s  << 24
               | (uint32_t)s  << 16
               | (uint32_t)s2 << 8
               | (uint32_t)s3;

        Te2[i] = (uint32_t)s  << 24
               | (uint32_t)s2 << 16
               | (uint32_t)s3 << 8
               | (uint32_t)s;

        Te3[i] = (uint32_t)s2 << 24
               | (uint32_t)s3 << 16
               | (uint32_t)s  <<  8
               | (uint32_t)s;
    }
    tables_generated = true;
}


/**
 * Precomputes AES decryption T-tables (Td0 - Td3) for fast
 * InvSubBytes + InvShiftRows + InvMixColumns.
 *
 * Uses aes_inv_sbox[i] to get the inverse-substituted byte s,
 * then forms s2 = 2·s, s4 = 4·s, s8 = 8·s, and from those
 * builds:
 *   s9 =  s8 ^ s       (9·s)
 *   sb =  s8 ^ s2 ^ s  (0x0b·s)
 *   sd =  s8 ^ s4 ^ s  (0x0d·s)
 *   se =  s8 ^ s4 ^ s2 (0x0e·s)
 *
 * Finally, each Td-table packs these four multiplications
 * into a 32-bit little-endian word, and rotates for Td1–Td3.
 */
static void generate_inv_tables(void) {
    for (int i = 0; i < 256; i++) {
        uint8_t s  = aes_inv_sbox[i];
        uint8_t s2 = (uint8_t)(s << 1) ^ (uint8_t)((s >> 7) * 0x1B);
        uint8_t s4 = (uint8_t)(s2 << 1) ^ (uint8_t)((s2 >> 7) * 0x1B);
        uint8_t s8 = (uint8_t)(s4 << 1) ^ (uint8_t)((s4 >> 7) * 0x1B);

        uint8_t s9 = s8 ^ s;
        uint8_t sb = s8 ^ s2 ^ s;
        uint8_t sd = s8 ^ s4 ^ s;
        uint8_t se = s8 ^ s4 ^ s2;

        // Td0: [0x0e·s, 0x0b·s, 0x0d·s, 0x09·s]
        Td0[i] = ((uint32_t)se << 24)
               | ((uint32_t)sb << 16)
               | ((uint32_t)sd <<  8)
               | (uint32_t)s9;

        // rotate byte-wise for Td1–Td3
        Td1[i] = (Td0[i] << 8)  | (Td0[i] >> 24);
        Td2[i] = (Td1[i] << 8)  | (Td1[i] >> 24);
        Td3[i] = (Td2[i] << 8)  | (Td2[i] >> 24);
    }
    inv_tables_generated = true;
}


/**
 * Encrypts a single 16-byte block of data in-place using AES with precomputed T-tables.
 *
 * This function performs AES encryption on the block at index `block_index`
 * inside the `data[]` buffer. It uses four “T-tables” (Te0–Te3) for efficient
 * SubBytes+ShiftRows+MixColumns in the middle rounds and falls back to the
 * raw S-box (aes_sbox) for the final round. On first invocation, it calls
 * generate_tables() to build Te0–Te3 as 256-entry lookup tables in little-endian
 * form:
 *   • Te0–Te3 combine SubBytes, ShiftRows, and MixColumns so that during each
 *     middle round, four bytes of the current state (selected by fixed offsets)
 *     can be XOR’d together and with the round key, producing a ready-to-store
 *     32-bit little-endian result for each column.
 *
 * After table generation, ttable_aes_encrypt does the following steps:
 *   1. Let `state` point to the 16 bytes of the chosen block (as four little-endian
 *      uint32_t words). Apply the initial AddRoundKey by XOR’ing these four words
 *      with the first round key.
 *   2. For each middle round (round = 1..n_rounds–1):
 *      • Call `callback(...)` so the caller can yield or track progress if desired.
 *      • Read the four “ShiftRows” bytes for each column directly from `data[]`
 *        (e.g., column 0 reads bytes at indices 0, 5, 10, 15; column 1 reads 4, 9, 14, 3, etc.).
 *      • Look up each of those four bytes in Te0, Te1, Te2, Te3 respectively,
 *        XOR the four 32-bit table entries together, then XOR with the 32-bit
 *        round key for that column. Store each resulting 32-bit little-endian
 *        word back into the corresponding four bytes of `state[]`.
 *   3. In the final round:
 *      • Instead of using a fifth T-table, explicitly apply SubBytes+ShiftRows
 *        by indexing the raw AES S-box (`aes_sbox[<byte>]`) at offsets 0, 5, 10, 15
 *        (for column 0), 4, 9, 14, 3 (column 1), and so on.
 *      • Pack each group of four S-box outputs into a 32-bit word (using shifts),
 *        XOR that word with the final 32-bit round key, and store it back into
 *        the same `state[]` words. This completes SubBytes, ShiftRows, and
 *        AddRoundKey for the last round (MixColumns is omitted).
 *
 * Because Te0–Te3 are precomputed in little-endian form, no runtime byte-swapping
 * is required. Each round updates the 16 bytes of `data[]` in-place, so when the
 * loop finishes, the block at `data + block_index*16` contains the final ciphertext.
 *
 * Parameters:
 *   data[]        – Byte array containing one or more 16-byte blocks. The block
 *                   to encrypt lives at offset `(block_index * 16)`.
 *
 *   round_keys    – An array of AES round keys. Each entry is exactly 16 bytes.
 *                   There must be `block_count * key_count` total entries, laid
 *                   out so that the keys for block 'i' start at `round_keys[i*key_count]`.
 *
 *   key_count     – Total number of 16-byte round keys per block (i.e., AES rounds + 1).
 *
 *   block_count   – Number of 16-byte blocks stored in `data[]`.
 *
 *   block_index   – Zero-based index of the block to encrypt within `data[]`.
 *
 *   callback      – Function of the type `AES_YieldCallback` that is invoked once at the
 *                   start of each middle round. Can be used for yielding or progress
 *                   updates.
 *
 * Returns:
 *   None. In return, the 16 bytes at `data + block_index*16` have been replaced
 *   with the encrypted AES ciphertext for that block.
 */
void ttable_aes_encrypt(
        uint8_t data[],
        const uint8_t round_keys[][16],
        const uint8_t key_count,
        const uint8_t block_count,
        const uint8_t block_index,
        const AES_YieldCallback callback
) {
    if (!tables_generated) {
        generate_tables();
    }
    uint32_t *state = (uint32_t *)(data + block_index * 16);
    const uint8_t *b = data + block_index * 16;

    const uint8_t (*keys)[16] = &round_keys[block_index * key_count];
    const uint8_t n_rounds = key_count - 1;

    // First round
    {
        const uint32_t *rkey = (uint32_t *)keys[0];

        state[0] ^= rkey[0];
        state[1] ^= rkey[1];
        state[2] ^= rkey[2];
        state[3] ^= rkey[3];
    }

    // Middle rounds
    for (uint8_t round = 1; round < n_rounds; round++) {
        callback(
            data,
            round_keys,
            key_count,
            block_count,
            block_index + 1
        );
        const uint32_t *rkey = (uint32_t *)keys[round];

        const uint32_t t0 = Te0[b[0]] ^ Te1[b[5]] ^ Te2[b[10]] ^ Te3[b[15]];
        const uint32_t t1 = Te0[b[4]] ^ Te1[b[9]] ^ Te2[b[14]] ^ Te3[b[3]];
        const uint32_t t2 = Te0[b[8]] ^ Te1[b[13]] ^ Te2[b[2]] ^ Te3[b[7]];
        const uint32_t t3 = Te0[b[12]] ^ Te1[b[1]] ^ Te2[b[6]] ^ Te3[b[11]];

        state[0] = t0 ^ rkey[0];
        state[1] = t1 ^ rkey[1];
        state[2] = t2 ^ rkey[2];
        state[3] = t3 ^ rkey[3];
    }

    // Final round
    {
        const uint32_t* rkey = (uint32_t*)keys[n_rounds];

        const uint32_t t0 = aes_sbox[b[0]]
                          | aes_sbox[b[5]] << 8
                          | aes_sbox[b[10]] << 16
                          | aes_sbox[b[15]] << 24;

        const uint32_t t1 = aes_sbox[b[4]]
                          | aes_sbox[b[9]] << 8
                          | aes_sbox[b[14]] << 16
                          | aes_sbox[b[3]] << 24;

        const uint32_t t2 = aes_sbox[b[8]]
                          | aes_sbox[b[13]] << 8
                          | aes_sbox[b[2]] << 16
                          | aes_sbox[b[7]] << 24;

        const uint32_t t3 = aes_sbox[b[12]]
                          | aes_sbox[b[1]] << 8
                          | aes_sbox[b[6]] << 16
                          | aes_sbox[b[11]] << 24;

        state[0] = t0 ^ rkey[0];
        state[1] = t1 ^ rkey[1];
        state[2] = t2 ^ rkey[2];
        state[3] = t3 ^ rkey[3];
    }
}


// ================================================================================
// AES decryption
// ================================================================================

/*
 * Applies the SubBytes transformation to the 16-byte AES state in-place.
 */
void sub_bytes(uint8_t state[16], const uint8_t sbox[256]) {
    state[0]  = sbox[state[0]];
    state[1]  = sbox[state[1]];
    state[2]  = sbox[state[2]];
    state[3]  = sbox[state[3]];
    state[4]  = sbox[state[4]];
    state[5]  = sbox[state[5]];
    state[6]  = sbox[state[6]];
    state[7]  = sbox[state[7]];
    state[8]  = sbox[state[8]];
    state[9]  = sbox[state[9]];
    state[10] = sbox[state[10]];
    state[11] = sbox[state[11]];
    state[12] = sbox[state[12]];
    state[13] = sbox[state[13]];
    state[14] = sbox[state[14]];
    state[15] = sbox[state[15]];
}


/*
 * Applies the AES InvShiftRows transformation in-place on a 16-byte state.
 */
void inv_shift_rows(uint8_t state[16]) {
    // Row 1 (indices 1,5,9,13): right rotate by 1 (equiv. left rotate by 3)
    uint8_t tmp = state[13];
    state[13]   = state[9];
    state[9]    = state[5];
    state[5]    = state[1];
    state[1]    = tmp;

    // Row 2 (indices 2,6,10,14): right rotate by 2
    tmp       = state[2];
    state[2]  = state[10];
    state[10] = tmp;
    tmp       = state[6];
    state[6]  = state[14];
    state[14] = tmp;

    // Row 3 (indices 3,7,11,15): right rotate by 3 (equiv. left rotate by 1)
    tmp       = state[3];
    state[3]  = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = tmp;
}


/*
 * Multiplies a byte by {02} in GF(2^8)
 */
uint8_t xtime(const uint8_t a) {
    const uint8_t x = (uint8_t)(a << 1);
    const uint8_t y = (uint8_t)(a >> 7);
    return x ^ (uint8_t)(y * 0x1B);
}


/**
 * Applies the AES MixColumns transformation to one 4-byte column.
 */
void mix_single_column(uint8_t state[16], const uint8_t i) {
    const uint8_t a = i;
    const uint8_t b = i + 1;
    const uint8_t c = i + 2;
    const uint8_t d = i + 3;

    const uint8_t x = (uint8_t)(state[a] ^ state[b] ^ state[c] ^ state[d]);
    const uint8_t y = state[a];

    state[a] = (uint8_t)(state[a] ^ x ^ xtime((uint8_t)(state[a] ^ state[b])));
    state[b] = (uint8_t)(state[b] ^ x ^ xtime((uint8_t)(state[b] ^ state[c])));
    state[c] = (uint8_t)(state[c] ^ x ^ xtime((uint8_t)(state[c] ^ state[d])));
    state[d] = (uint8_t)(state[d] ^ x ^ xtime((uint8_t)(state[d] ^ y)));
}


/**
 * Apply the AES InvMixColumns transformation to one 4-byte column.
 */
void inv_mix_single_column(uint8_t state[16], const uint8_t i) {
    const uint8_t a = i;
    const uint8_t b = i + 1;
    const uint8_t c = i + 2;
    const uint8_t d = i + 3;

    const uint8_t m = (uint8_t)(state[a] ^ state[c]);
    const uint8_t n = (uint8_t)(state[b] ^ state[d]);
    const uint8_t x = xtime(xtime(m));
    const uint8_t y = xtime(xtime(n));

    state[a] = (uint8_t)(state[a] ^ x);
    state[b] = (uint8_t)(state[b] ^ y);
    state[c] = (uint8_t)(state[c] ^ x);
    state[d] = (uint8_t)(state[d] ^ y);
}


/**
 * Applies the AES InvMixColumns transformation to the entire state.
 */
void inv_mix_columns(uint8_t state[16]) {
    inv_mix_single_column(state, 0);
    inv_mix_single_column(state, 4);
    inv_mix_single_column(state, 8);
    inv_mix_single_column(state, 12);
    mix_single_column(state, 0);
    mix_single_column(state, 4);
    mix_single_column(state, 8);
    mix_single_column(state, 12);
}


void ttable_aes_decrypt(
        uint8_t data[],
        const uint8_t round_keys[][16],
        const uint8_t key_count,
        const uint8_t block_count,
        const uint8_t block_index,
        const AES_YieldCallback callback
) {
    if (!inv_tables_generated) {
        generate_inv_tables();
    }
    uint32_t *state = (uint32_t *)(data + block_index * 16);
    const uint8_t *b = data + block_index * 16;

    const uint8_t (*keys)[16] = &round_keys[block_index * key_count];
    const uint8_t n_rounds = key_count - 1;

    // First round
    {
        const uint32_t *rkey = (uint32_t *)keys[n_rounds];

        state[0] ^= rkey[0];
        state[1] ^= rkey[1];
        state[2] ^= rkey[2];
        state[3] ^= rkey[3];

        const uint32_t t0 = aes_inv_sbox[b[0]]
                          | aes_inv_sbox[b[13]] << 8
                          | aes_inv_sbox[b[10]] << 16
                          | aes_inv_sbox[b[7]] << 24;

        const uint32_t t1 = aes_inv_sbox[b[4]]
                          | aes_inv_sbox[b[1]] << 8
                          | aes_inv_sbox[b[14]] << 16
                          | aes_inv_sbox[b[11]] << 24;

        const uint32_t t2 = aes_inv_sbox[b[8]]
                          | aes_inv_sbox[b[5]] << 8
                          | aes_inv_sbox[b[2]] << 16
                          | aes_inv_sbox[b[15]] << 24;

        const uint32_t t3 = aes_inv_sbox[b[12]]
                          | aes_inv_sbox[b[9]] << 8
                          | aes_inv_sbox[b[6]] << 16
                          | aes_inv_sbox[b[3]] << 24;

        state[0] = t0;
        state[1] = t1;
        state[2] = t2;
        state[3] = t3;
    }

    // Middle round
    uint8_t *state8 = data + block_index * 16;
    for (uint8_t round = n_rounds - 1; round > 0; round--) {
        const uint32_t *rkey = (uint32_t *)keys[round];

        state[0] ^= rkey[0];
        state[1] ^= rkey[1];
        state[2] ^= rkey[2];
        state[3] ^= rkey[3];

        // add_round_key(state8, keys, round);
        inv_mix_columns(state8);
        inv_shift_rows(state8);
        sub_bytes(state8, aes_inv_sbox);

        callback(
            data,
            round_keys,
            key_count,
            block_count,
            block_index + 1
        );
    }

    // Final round
    {
        const uint32_t *rkey = (uint32_t *)keys[0];

        state[0] ^= rkey[0];
        state[1] ^= rkey[1];
        state[2] ^= rkey[2];
        state[3] ^= rkey[3];
    }
}