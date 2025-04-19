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

import pytest
from copy import deepcopy

from src.aes_block import Operation, AESBlock
from src.aes_sbox import SBox
from src.blake_keygen import KDFDomain, BlakeKeyGen

__all__ = [
    "fixture_aes_block",
    "test_encrypt_decrypt",
    "test_mix_columns",
    "test_shift_rows",
    "test_add_round_key",
    "test_sub_bytes",
]


class AESBlockTester(AESBlock):
    initial_data: list[int]


@pytest.fixture(name="aes_block", scope="function")
def fixture_aes_block() -> AESBlockTester:
    keygen = BlakeKeyGen(bytes(64), bytes(32))
    keygen.digest_context(b"")
    round_keys = keygen.compute_round_keys(counter=0, domain=KDFDomain.CIPHER_OPS)
    data = [
        0x87, 0xF2, 0x4D, 0x97,
        0x6E, 0x4C, 0x90, 0xEC,
        0x46, 0xE7, 0x4A, 0xC3,
        0xA6, 0x8C, 0xD8, 0x95,
    ]
    block = AESBlockTester(data, round_keys, Operation.ENCRYPT)
    for idx, uint8 in enumerate(block.state):
        assert data[idx] == uint8.value
    assert len(block.round_keys) == 11
    for key_set in block.round_keys:
        assert len(key_set) == 16
    block.initial_data = deepcopy(data)
    return block


def test_encrypt_decrypt(aes_block):
    assert aes_block.state == aes_block.initial_data
    for _ in aes_block.encryption_generator():
        pass
    assert aes_block.state == [
        0x3A, 0xF6, 0x12, 0x41,
        0xFA, 0xE6, 0x2E, 0x7D,
        0x52, 0x32, 0xFB, 0x79,
        0xC0, 0x0E, 0x97, 0x27,
    ]
    for _ in aes_block.decryption_generator():
        pass
    assert aes_block.state == aes_block.initial_data


def test_mix_columns(aes_block):
    assert aes_block.state == aes_block.initial_data
    aes_block.mix_columns()
    assert aes_block.state == [
        0xC2, 0x38, 0x4D, 0x18,
        0x74, 0xB1, 0x36, 0xAD,
        0x37, 0x8E, 0x6B, 0xFA,
        0x95, 0x43, 0x25, 0x94,
    ]
    aes_block.inv_mix_columns()
    assert aes_block.state == aes_block.initial_data


def test_shift_rows(aes_block):
    assert aes_block.state == aes_block.initial_data
    aes_block.shift_rows()
    assert aes_block.state == [
        0x87, 0x4C, 0x4A, 0x95,
        0x6E, 0xE7, 0xD8, 0x97,
        0x46, 0x8C, 0x4D, 0xEC,
        0xA6, 0xF2, 0x90, 0xC3,
    ]
    aes_block.inv_shift_rows()
    assert aes_block.state == aes_block.initial_data


def test_add_round_key(aes_block):
    assert aes_block.state == aes_block.initial_data
    aes_block.add_round_key(index=0)
    assert aes_block.state == [
        0x9B, 0xDC, 0x76, 0x3B,
        0x8E, 0x4A, 0x30, 0x2F,
        0xF9, 0x80, 0x0C, 0x23,
        0x3B, 0x7B, 0x3D, 0x6C,
    ]
    aes_block.add_round_key(index=0)
    assert aes_block.state == aes_block.initial_data


def test_sub_bytes(aes_block):
    assert aes_block.state == aes_block.initial_data
    aes_block.sub_bytes(SBox.ENC)
    assert aes_block.state == [
        0x17, 0x89, 0xE3, 0x88,
        0x9F, 0x29, 0x60, 0xCE,
        0x5A, 0x94, 0xD6, 0x2E,
        0x24, 0x64, 0x61, 0x2A,
    ]
    aes_block.sub_bytes(SBox.DEC)
    assert aes_block.state == aes_block.initial_data
