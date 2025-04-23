#
#   Apache License 2.0
#
#   Copyright (c) 2024, Mattias Aabmets
#
#   The contents of this file are subject to the terms and conditions defined in the License.
#   You may not use, modify, or distribute this file except in compliance with the License.
#
#   SPDX-License-Identifier: Apache-2.0
#

import secrets

from src.uint import Uint8
from src.aes_sbox import SBox
from src.aes_block import AESBlock

__all__ = [
    "generate_original_aes128_round_keys",
    "test_fips197_example_vectors",
    "test_random_secret_key",
]


def generate_original_aes128_round_keys(key: bytes) -> list[list[Uint8]]:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    Nk = 4
    Nb = 4
    Nr = 10
    key_bytes = [Uint8(b) for b in key]
    w: list[list[Uint8]] = []
    for i in range(Nk):
        w.append(key_bytes[4*i:4*i+4])
    rcon = [Uint8(r) for r in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)]
    for i in range(Nk, Nb*(Nr+1)):
        temp = w[i-1].copy()
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [Uint8(SBox.ENC.value[b.value]) for b in temp]
            temp[0] ^= rcon[i//Nk - 1]
        w.append([w[i-Nk][j] ^ temp[j] for j in range(4)])
    round_keys: list[list[Uint8]] = []
    for r in range(Nr+1):
        round_key = []
        for word in w[4*r : 4*r+4]:
            round_key.extend(word)
        round_keys.append(round_key)
    return round_keys


def test_fips197_example_vectors():
    vectors = [
        dict(
            plaintext=bytes.fromhex("3243f6a8885a308d313198a2e0370734"),
            secret_key=bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
            expected_ct=bytes.fromhex("3925841d02dc09fbdc118597196a0b32"),
        ),
        dict(
            plaintext=bytes.fromhex("00112233445566778899aabbccddeeff"),
            secret_key=bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
            expected_ct=bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        )
    ]
    for v in vectors:
        round_keys = generate_original_aes128_round_keys(v["secret_key"])
        aes1 = AESBlock(v["plaintext"], round_keys)
        ciphertext = aes1.encrypt()

        assert ciphertext == v["expected_ct"]

        round_keys = generate_original_aes128_round_keys(v["secret_key"])
        aes2 = AESBlock(ciphertext, round_keys)
        plaintext = aes2.decrypt()

        assert plaintext == v["plaintext"]


def test_random_secret_key():
    secret_key = secrets.token_bytes(16)
    original_pt = bytes(range(16))

    round_keys = generate_original_aes128_round_keys(secret_key)
    aes1 = AESBlock(original_pt, round_keys)
    ct = aes1.encrypt()

    round_keys = generate_original_aes128_round_keys(secret_key)
    aes2 = AESBlock(ct, round_keys)
    recovered_pt = aes2.decrypt()

    assert original_pt == recovered_pt
