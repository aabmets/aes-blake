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
import typing as t

from src.blake_keygen import KDFDomain
from src.aes_blake import AESBlake256, AESBlake512, BaseAESBlake

__all__ = [
    "fixture_aes_block_data",
    "normal_usage_tester",
    "bad_data_tester",
    "test_aesblake256_normal_usage",
    "test_aesblake512_normal_usage",
    "test_aesblake256_bad_key",
    "test_aesblake512_bad_key",
    "test_aesblake256_bad_nonce",
    "test_aesblake512_bad_nonce",
    "test_aesblake256_bad_context",
    "test_aesblake512_bad_context",
    "test_aesblake256_bad_ciphertext",
    "test_aesblake512_bad_ciphertext",
    "test_aesblake256_bad_header",
    "test_aesblake512_bad_header",
    "test_aesblake256_bad_auth_tag",
    "test_aesblake512_bad_auth_tag",
    "test_aesblake256_ex_cols",
    "test_aesblake512_ex_cols"
]


@pytest.fixture(name="aes_block_data", scope="function")
def fixture_aes_block_data() -> tuple[bytes, ...]:
    chunk1 = bytes([b for b in [0x1A, 0x2A, 0x3A, 0x4A] for _ in range(4)])
    chunk2 = bytes([b for b in [0x1B, 0x2B, 0x3B, 0x4B] for _ in range(4)])
    chunk3 = bytes([b for b in [0x1C, 0x2C, 0x3C, 0x4C] for _ in range(4)])
    chunk4 = bytes([b for b in [0x1D, 0x2D, 0x3D, 0x4D] for _ in range(4)])
    return chunk1, chunk2, chunk3, chunk4


def normal_usage_tester(cls: t.Type[BaseAESBlake]):
    data_len = cls.keygen_class().uint().bit_count()
    plaintext = header = bytes(range(data_len))
    cipher = cls(b"", b"", b"")
    ciphertext, auth_tag = cipher.encrypt(plaintext, header)
    _plaintext = cipher.decrypt(ciphertext, header, auth_tag)
    assert len(ciphertext) == data_len
    assert len(_plaintext) == data_len
    assert _plaintext == plaintext


def bad_data_tester(cls: t.Type[BaseAESBlake], corrupt_field: str):
    data_len = cls.keygen_class().uint().bit_count()
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


def test_aesblake256_normal_usage():
    normal_usage_tester(AESBlake256)


def test_aesblake512_normal_usage():
    normal_usage_tester(AESBlake512)


def test_aesblake256_bad_key():
    bad_data_tester(AESBlake256, "key")


def test_aesblake512_bad_key():
    bad_data_tester(AESBlake512, "key")


def test_aesblake256_bad_nonce():
    bad_data_tester(AESBlake256, "nonce")


def test_aesblake512_bad_nonce():
    bad_data_tester(AESBlake512, "nonce")


def test_aesblake256_bad_context():
    bad_data_tester(AESBlake256, "context")


def test_aesblake512_bad_context():
    bad_data_tester(AESBlake512, "context")


def test_aesblake256_bad_ciphertext():
    bad_data_tester(AESBlake256, "ciphertext")


def test_aesblake512_bad_ciphertext():
    bad_data_tester(AESBlake512, "ciphertext")


def test_aesblake256_bad_header():
    bad_data_tester(AESBlake256, "header")


def test_aesblake512_bad_header():
    bad_data_tester(AESBlake512, "header")


def test_aesblake256_bad_auth_tag():
    bad_data_tester(AESBlake256, "auth_tag")


def test_aesblake512_bad_auth_tag():
    bad_data_tester(AESBlake512, "auth_tag")


def test_aesblake256_ex_cols(aes_block_data):
    chunks = aes_block_data[:2]
    cipher = AESBlake256(b'', b'', b'')
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


def test_aesblake512_ex_cols(aes_block_data):
    chunks = aes_block_data
    cipher = AESBlake512(b'', b'', b'')
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
