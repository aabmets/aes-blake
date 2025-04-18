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

from src.aes_block import Operation, AESBlock
from src.aes_sbox import SBox
from src.blake_keygen import BlakeKeyGen

__all__ = [
    "fixture_aes_block",
    "test_encrypt_decrypt",
    "test_mix_columns",
    "test_shift_rows",
    "test_add_round_key",
    "test_sub_bytes",
]


@pytest.fixture(name="aes_block", scope="function")
def fixture_aes_block() -> AESBlock:
    keygen = BlakeKeyGen(b"", b"", b"")
    round_keys = keygen.compute_aes_round_keys(counter=0)
    data = [
        0x87, 0xF2, 0x4D, 0x97,
        0x6E, 0x4C, 0x90, 0xEC,
        0x46, 0xE7, 0x4A, 0xC3,
        0xA6, 0x8C, 0xD8, 0x95,
    ]
    block = AESBlock(data, round_keys, Operation.ENCRYPT)
    for idx, uint8 in enumerate(block.state):
        assert data[idx] == uint8.value
    assert len(block.round_keys) == 11
    for key_set in block.round_keys:
        assert len(key_set) == 16
    return block


def test_encrypt_decrypt(aes_block):
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0x87, 0xF2, 0x4D, 0x97,
        0x6E, 0x4C, 0x90, 0xEC,
        0x46, 0xE7, 0x4A, 0xC3,
        0xA6, 0x8C, 0xD8, 0x95,
    ]
    for _ in aes_block.encryption_generator():
        pass
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0xC4, 0xC5, 0x04, 0x84,
        0x3F, 0x51, 0x6A, 0xED,
        0xAC, 0xC3, 0x31, 0x12,
        0x85, 0x54, 0xE6, 0x0B,
    ]
    for _ in aes_block.decryption_generator():
        pass
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0x87, 0xF2, 0x4D, 0x97,
        0x6E, 0x4C, 0x90, 0xEC,
        0x46, 0xE7, 0x4A, 0xC3,
        0xA6, 0x8C, 0xD8, 0x95,
    ]


def test_mix_columns(aes_block):
    aes_block.mix_columns()
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0xC2, 0x38, 0x4D, 0x18,
        0x74, 0xB1, 0x36, 0xAD,
        0x37, 0x8E, 0x6B, 0xFA,
        0x95, 0x43, 0x25, 0x94,
    ]
    aes_block.inv_mix_columns()
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0x87, 0xF2, 0x4D, 0x97,
        0x6E, 0x4C, 0x90, 0xEC,
        0x46, 0xE7, 0x4A, 0xC3,
        0xA6, 0x8C, 0xD8, 0x95,
    ]


def test_shift_rows(aes_block):
    aes_block.shift_rows()
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0x87, 0x4C, 0x4A, 0x95,
        0x6E, 0xE7, 0xD8, 0x97,
        0x46, 0x8C, 0x4D, 0xEC,
        0xA6, 0xF2, 0x90, 0xC3,
    ]
    aes_block.inv_shift_rows()
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0x87, 0xF2, 0x4D, 0x97,
        0x6E, 0x4C, 0x90, 0xEC,
        0x46, 0xE7, 0x4A, 0xC3,
        0xA6, 0x8C, 0xD8, 0x95,
    ]


def test_add_round_key(aes_block):
    aes_block.add_round_key(0)
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0x8F, 0x80, 0x01, 0xB8,
        0x2C, 0x26, 0xCC, 0xCB,
        0x6A, 0x67, 0x02, 0x68,
        0x30, 0xDD, 0xF5, 0x09,
    ]
    aes_block.add_round_key(0)
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0x87, 0xF2, 0x4D, 0x97,
        0x6E, 0x4C, 0x90, 0xEC,
        0x46, 0xE7, 0x4A, 0xC3,
        0xA6, 0x8C, 0xD8, 0x95,
    ]


def test_sub_bytes(aes_block):
    aes_block.sub_bytes(SBox.ENC)
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0x17, 0x89, 0xE3, 0x88,
        0x9F, 0x29, 0x60, 0xCE,
        0x5A, 0x94, 0xD6, 0x2E,
        0x24, 0x64, 0x61, 0x2A,
    ]
    aes_block.sub_bytes(SBox.DEC)
    values = [obj.value for obj in aes_block.state]
    assert values == [
        0x87, 0xF2, 0x4D, 0x97,
        0x6E, 0x4C, 0x90, 0xEC,
        0x46, 0xE7, 0x4A, 0xC3,
        0xA6, 0x8C, 0xD8, 0x95,
    ]
