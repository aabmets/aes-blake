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
import typing as t
from copy import deepcopy
from functools import cache
from multiprocessing import Lock

import pytest

from src.aes_block import *
from src.blake_keygen import RoundKeys
from src.integers import *

__all__ = [
    "generate_original_aes128_round_keys",
    "AESBlockWithKeygen",
    "MaskedAESBlockWithKeygen",
    "test_fips197_example_vectors",
    "test_random_secret_key",
]

LOCK = Lock()


@cache
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


class AESBlockWithKeygen(AESBlock):
    @staticmethod
    def gen_original_round_keys(secret_key: bytes) -> RoundKeys:
        with LOCK:
            return generate_original_aes128_round_keys(secret_key)


class MaskedAESBlockWithKeygen(MaskedAESBlock):
    @staticmethod
    def gen_original_round_keys(secret_key: bytes) -> RoundKeys:
        with LOCK:
            round_keys = generate_original_aes128_round_keys(secret_key)
            for key_set in round_keys:
                for i, key in enumerate(key_set):
                    key_set[i] = t.cast(Uint8, MaskedUint8(key))
            return round_keys


@pytest.mark.parametrize("cls", [AESBlockWithKeygen, MaskedAESBlockWithKeygen])
@pytest.mark.parametrize("vector", [
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
])
def test_fips197_example_vectors(cls, vector):
    round_keys = cls.gen_original_round_keys(vector["secret_key"])

    aes1 = cls(vector["plaintext"], deepcopy(round_keys))
    for _ in aes1.encrypt():
        pass
    assert aes1.output == vector["expected_ct"]

    aes2 = cls(aes1.output, deepcopy(round_keys))
    for _ in aes2.decrypt():
        pass
    assert aes2.output == vector["plaintext"]


@pytest.mark.parametrize("cls", [AESBlockWithKeygen, MaskedAESBlockWithKeygen])
def test_random_secret_key(cls):
    plaintext = bytes(range(16))
    secret_key = secrets.token_bytes(16)
    round_keys = cls.gen_original_round_keys(secret_key)

    aes1 = cls(plaintext, deepcopy(round_keys))
    for _ in aes1.encrypt():
        pass

    aes2 = cls(aes1.output, deepcopy(round_keys))
    for _ in aes2.decrypt():
        pass
    assert aes2.output == plaintext
