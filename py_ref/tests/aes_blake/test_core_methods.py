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

from src.aes_blake import AESBlake256, AESBlake512
from src.blake_keygen import KDFDomain
from tests.aes_blake.overrides import (PartiallyMockedMaskedAESBlake256,
                                       PartiallyMockedMaskedAESBlake512)

__all__ = [
    "CLEAN_CLASSES",
    "MASKED_CLASSES",
    "ALL_CLASSES",
    "fixture_aes_block_data",
    "test_split_bytes",
    "test_group_by_valid",
    "test_group_by_invalid",
    "test_clean_aesblake_normal_usage",
    "test_masked_aesblake_normal_usage",
    "test_clean_aesblake_bad_data",
    "test_masked_aesblake_bad_data",
    "test_aesblake256_ex_cols",
    "test_aesblake512_ex_cols"
]

CLEAN_CLASSES = [AESBlake256, AESBlake512]
MASKED_CLASSES = [PartiallyMockedMaskedAESBlake256, PartiallyMockedMaskedAESBlake512]
ALL_CLASSES = CLEAN_CLASSES + MASKED_CLASSES


@pytest.fixture(name="aes_block_data", scope="function")
def fixture_aes_block_data() -> tuple[bytes, ...]:
    chunk1 = bytes([b for b in [0x1A, 0x2A, 0x3A, 0x4A] for _ in range(4)])
    chunk2 = bytes([b for b in [0x1B, 0x2B, 0x3B, 0x4B] for _ in range(4)])
    chunk3 = bytes([b for b in [0x1C, 0x2C, 0x3C, 0x4C] for _ in range(4)])
    chunk4 = bytes([b for b in [0x1D, 0x2D, 0x3D, 0x4D] for _ in range(4)])
    return chunk1, chunk2, chunk3, chunk4


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_split_bytes(cls):
    data = b"Word1Word2Word3Word4Word5"
    chunks = cls.split_bytes(data, chunk_size=5)
    assert chunks == [b'Word1', b'Word2', b'Word3', b'Word4', b'Word5']
    chunks = cls.split_bytes(data, chunk_size=6)
    assert chunks == [b'Word1W', b'ord2Wo', b'rd3Wor', b'd4Word', b'5']


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_group_by_valid(cls):
    cases = [
        (['abc', 'def', 'ghi', 'jkl'], 2, [('abc', 'def'), ('ghi', 'jkl')]),
        (['abc', 'def', 'ghi'], 3, [('abc', 'def', 'ghi')]),
        (['abc', 'def'], 1, [('abc',), ('def',)])
    ]
    for data, size, expected in cases:
        assert cls.group_by(data, size) == expected


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_group_by_invalid(cls):
    cases = [
        ([], 1),
        (['abc', 'def'], 0),
        (['abc', 'def'], -1),
        (['abc', 'def', 'ghi'], 2),
    ]
    for data, size in cases:
        with pytest.raises(ValueError):
            cls.group_by(data, size)


@pytest.mark.parametrize("cls", CLEAN_CLASSES)
def test_clean_aesblake_normal_usage(cls):
    data_len = cls.keygen_class().bit_length()  # interpret as byte count
    plaintext = header = bytes(range(data_len))
    cipher = cls(b"", b"", b"")
    ciphertext, auth_tag = cipher.encrypt(plaintext, header)
    _plaintext = cipher.decrypt(ciphertext, header, auth_tag)
    assert len(plaintext) == data_len
    assert len(ciphertext) == data_len
    assert len(auth_tag) == data_len
    assert len(_plaintext) == data_len
    assert _plaintext == plaintext


@pytest.mark.with_slow_dom
@pytest.mark.parametrize("cls", MASKED_CLASSES)
def test_masked_aesblake_normal_usage(cls):
    test_clean_aesblake_normal_usage(cls)


@pytest.mark.parametrize("cls", CLEAN_CLASSES)
@pytest.mark.parametrize("corrupt_field", ["key", "nonce", "context", "ciphertext", "header", "auth_tag"])
def test_clean_aesblake_bad_data(cls, corrupt_field):
    data_len = cls.keygen_class().bit_length()
    key = nonce = context = header = plaintext = bytes(range(data_len))

    cipher = cls(key, nonce, context)
    ciphertext, auth_tag = cipher.encrypt(plaintext, header)

    data = dict(
        key=key,
        nonce=nonce,
        context=context,
        ciphertext=ciphertext,
        header=header,
        auth_tag=auth_tag,
    )
    for k, v in data.items():
        if k == corrupt_field:
            data[k] = bytes([v[0] ^ 0x01]) + v[1:]  # flip bit

    key, nonce, context, ciphertext, header, auth_tag = data.values()
    cipher = cls(key, nonce, context)
    with pytest.raises(ValueError, match="Failed to verify auth tag"):
        cipher.decrypt(ciphertext, header, auth_tag)


@pytest.mark.with_slow_dom
@pytest.mark.parametrize("cls", MASKED_CLASSES)
def test_masked_aesblake_bad_data(cls):
    test_clean_aesblake_bad_data(cls)


@pytest.mark.parametrize("cls", [AESBlake256, PartiallyMockedMaskedAESBlake256])
def test_aesblake256_ex_cols(cls, aes_block_data):
    cipher = cls(b'', b'', b'')
    chunks = aes_block_data[:2]
    aes_blocks = cipher.create_aes_blocks(chunks, KDFDomain.CHK)

    cipher.exchange_columns(aes_blocks)
    assert aes_blocks[0].state == [
        0x1A, 0x1A, 0x1A, 0x1A,  # 1A
        0x2B, 0x2B, 0x2B, 0x2B,  # 2B
        0x3A, 0x3A, 0x3A, 0x3A,  # 3A
        0x4B, 0x4B, 0x4B, 0x4B,  # 4B
    ]
    assert aes_blocks[1].state == [
        0x1B, 0x1B, 0x1B, 0x1B,  # 1B
        0x2A, 0x2A, 0x2A, 0x2A,  # 2A
        0x3B, 0x3B, 0x3B, 0x3B,  # 3B
        0x4A, 0x4A, 0x4A, 0x4A,  # 4A
    ]

    cipher.exchange_columns(aes_blocks, inverse=True)
    assert bytes(aes_blocks[0].state) == chunks[0]
    assert bytes(aes_blocks[1].state) == chunks[1]


@pytest.mark.parametrize("cls", [AESBlake512, PartiallyMockedMaskedAESBlake512])
def test_aesblake512_ex_cols(cls, aes_block_data):
    cipher = cls(b'', b'', b'')
    chunks = aes_block_data
    aes_blocks = cipher.create_aes_blocks(chunks, KDFDomain.CHK)

    cipher.exchange_columns(aes_blocks)
    assert aes_blocks[0].state == [
        0x1A, 0x1A, 0x1A, 0x1A,  # 1A
        0x2B, 0x2B, 0x2B, 0x2B,  # 2B
        0x3C, 0x3C, 0x3C, 0x3C,  # 3C
        0x4D, 0x4D, 0x4D, 0x4D,  # 4D
    ]
    assert aes_blocks[1].state == [
        0x1B, 0x1B, 0x1B, 0x1B,  # 1B
        0x2C, 0x2C, 0x2C, 0x2C,  # 2C
        0x3D, 0x3D, 0x3D, 0x3D,  # 3D
        0x4A, 0x4A, 0x4A, 0x4A,  # 4A
    ]
    assert aes_blocks[2].state == [
        0x1C, 0x1C, 0x1C, 0x1C,  # 1C
        0x2D, 0x2D, 0x2D, 0x2D,  # 2D
        0x3A, 0x3A, 0x3A, 0x3A,  # 3A
        0x4B, 0x4B, 0x4B, 0x4B,  # 4B
    ]
    assert aes_blocks[3].state == [
        0x1D, 0x1D, 0x1D, 0x1D,  # 1D
        0x2A, 0x2A, 0x2A, 0x2A,  # 2A
        0x3B, 0x3B, 0x3B, 0x3B,  # 3B
        0x4C, 0x4C, 0x4C, 0x4C,  # 4C
    ]

    cipher.exchange_columns(aes_blocks, inverse=True)
    assert bytes(aes_blocks[0].state) == chunks[0]
    assert bytes(aes_blocks[1].state) == chunks[1]
    assert bytes(aes_blocks[2].state) == chunks[2]
    assert bytes(aes_blocks[3].state) == chunks[3]
