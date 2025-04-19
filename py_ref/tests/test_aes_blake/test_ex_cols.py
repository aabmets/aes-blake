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

import collections.abc as c

import pytest

from src.aes_blake import AESBlake, BlockSize
from src.aes_block import Operation, AESBlock
from src.blake_keygen import KDFDomain, BlakeKeyGen

__all__ = [
    "fixture_blocks_data",
    "fixture_create_blocks",
    "test_exchange_columns_128",
    "test_exchange_columns_256",
    "test_exchange_columns_384",
    "test_exchange_columns_512",
]


@pytest.fixture(name="blocks_data", scope="function")
def fixture_blocks_data() -> list[bytes]:
    data1 = bytes([b for b in [0x1A, 0x2A, 0x3A, 0x4A] for _ in range(4)])
    data2 = bytes([b for b in [0x1B, 0x2B, 0x3B, 0x4B] for _ in range(4)])
    data3 = bytes([b for b in [0x1C, 0x2C, 0x3C, 0x4C] for _ in range(4)])
    data4 = bytes([b for b in [0x1D, 0x2D, 0x3D, 0x4D] for _ in range(4)])
    return [data1, data2, data3, data4]


@pytest.fixture(name="create_blocks", scope="function")
def fixture_create_blocks(blocks_data) -> c.Callable[[], list[AESBlock]]:
    def closure() -> list[AESBlock]:
        keygen = BlakeKeyGen(key=bytes(64), nonce=bytes(32))
        keygen.digest_context(context=bytes(128))
        round_keys = keygen.compute_round_keys(counter=0, domain=KDFDomain.CIPHER_OPS)
        block1 = AESBlock(blocks_data[0], round_keys, Operation.ENCRYPT)
        block2 = AESBlock(blocks_data[1], round_keys, Operation.ENCRYPT)
        block3 = AESBlock(blocks_data[2], round_keys, Operation.ENCRYPT)
        block4 = AESBlock(blocks_data[3], round_keys, Operation.ENCRYPT)
        return [block1, block2, block3, block4]
    return closure


def test_exchange_columns_128(create_blocks, blocks_data):
    cipher = AESBlake(key=bytes(64), context=bytes(128), block_size=BlockSize.BITS_128)
    blocks = create_blocks()

    cipher.exchange_columns(blocks)
    assert bytes(blocks[0].state) == blocks_data[0]
    assert bytes(blocks[1].state) == blocks_data[1]
    assert bytes(blocks[2].state) == blocks_data[2]
    assert bytes(blocks[3].state) == blocks_data[3]

    cipher.exchange_columns(blocks, inverse=True)
    assert bytes(blocks[0].state) == blocks_data[0]
    assert bytes(blocks[1].state) == blocks_data[1]
    assert bytes(blocks[2].state) == blocks_data[2]
    assert bytes(blocks[3].state) == blocks_data[3]


def test_exchange_columns_256(create_blocks, blocks_data):
    cipher = AESBlake(key=bytes(64), context=bytes(128), block_size=BlockSize.BITS_256)
    blocks = create_blocks()

    cipher.exchange_columns(blocks)
    assert blocks[0].state == [
        0x1A, 0x1A, 0x1A, 0x1A,  # 1A
        0x2B, 0x2B, 0x2B, 0x2B,  # 2B
        0x3A, 0x3A, 0x3A, 0x3A,  # 3A
        0x4B, 0x4B, 0x4B, 0x4B,  # 4B
    ]
    assert blocks[1].state == [
        0x1B, 0x1B, 0x1B, 0x1B,  # 1B
        0x2A, 0x2A, 0x2A, 0x2A,  # 2A
        0x3B, 0x3B, 0x3B, 0x3B,  # 3B
        0x4A, 0x4A, 0x4A, 0x4A,  # 4A
    ]
    assert bytes(blocks[2].state) == blocks_data[2]
    assert bytes(blocks[3].state) == blocks_data[3]

    cipher.exchange_columns(blocks, inverse=True)
    assert bytes(blocks[0].state) == blocks_data[0]
    assert bytes(blocks[1].state) == blocks_data[1]
    assert bytes(blocks[2].state) == blocks_data[2]
    assert bytes(blocks[3].state) == blocks_data[3]


def test_exchange_columns_384(create_blocks, blocks_data):
    cipher = AESBlake(key=bytes(64), context=bytes(128), block_size=BlockSize.BITS_384)
    blocks = create_blocks()

    cipher.exchange_columns(blocks)
    assert blocks[0].state == [
        0x1A, 0x1A, 0x1A, 0x1A,  # 1A
        0x2B, 0x2B, 0x2B, 0x2B,  # 2B
        0x3C, 0x3C, 0x3C, 0x3C,  # 3C
        0x4A, 0x4A, 0x4A, 0x4A,  # 4A
    ]
    assert blocks[1].state == [
        0x1B, 0x1B, 0x1B, 0x1B,  # 1B
        0x2C, 0x2C, 0x2C, 0x2C,  # 2C
        0x3A, 0x3A, 0x3A, 0x3A,  # 3A
        0x4B, 0x4B, 0x4B, 0x4B,  # 4B
    ]
    assert blocks[2].state == [
        0x1C, 0x1C, 0x1C, 0x1C,  # 1C
        0x2A, 0x2A, 0x2A, 0x2A,  # 2A
        0x3B, 0x3B, 0x3B, 0x3B,  # 3B
        0x4C, 0x4C, 0x4C, 0x4C,  # 4C
    ]
    assert bytes(blocks[3].state) == blocks_data[3]

    cipher.exchange_columns(blocks, inverse=True)
    assert bytes(blocks[0].state) == blocks_data[0]
    assert bytes(blocks[1].state) == blocks_data[1]
    assert bytes(blocks[2].state) == blocks_data[2]
    assert bytes(blocks[3].state) == blocks_data[3]


def test_exchange_columns_512(create_blocks, blocks_data):
    cipher = AESBlake(key=bytes(64), context=bytes(128), block_size=BlockSize.BITS_512)
    blocks = create_blocks()

    cipher.exchange_columns(blocks)
    assert blocks[0].state == [
        0x1A, 0x1A, 0x1A, 0x1A,  # 1A
        0x2B, 0x2B, 0x2B, 0x2B,  # 2B
        0x3C, 0x3C, 0x3C, 0x3C,  # 3C
        0x4D, 0x4D, 0x4D, 0x4D,  # 4D
    ]
    assert blocks[1].state == [
        0x1B, 0x1B, 0x1B, 0x1B,  # 1B
        0x2C, 0x2C, 0x2C, 0x2C,  # 2C
        0x3D, 0x3D, 0x3D, 0x3D,  # 3D
        0x4A, 0x4A, 0x4A, 0x4A,  # 4A
    ]
    assert blocks[2].state == [
        0x1C, 0x1C, 0x1C, 0x1C,  # 1C
        0x2D, 0x2D, 0x2D, 0x2D,  # 2D
        0x3A, 0x3A, 0x3A, 0x3A,  # 3A
        0x4B, 0x4B, 0x4B, 0x4B,  # 4B
    ]
    assert blocks[3].state == [
        0x1D, 0x1D, 0x1D, 0x1D,  # 1D
        0x2A, 0x2A, 0x2A, 0x2A,  # 2A
        0x3B, 0x3B, 0x3B, 0x3B,  # 3B
        0x4C, 0x4C, 0x4C, 0x4C,  # 4C
    ]

    cipher.exchange_columns(blocks, inverse=True)
    assert bytes(blocks[0].state) == blocks_data[0]
    assert bytes(blocks[1].state) == blocks_data[1]
    assert bytes(blocks[2].state) == blocks_data[2]
    assert bytes(blocks[3].state) == blocks_data[3]
