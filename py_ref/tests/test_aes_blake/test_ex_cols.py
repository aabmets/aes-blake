#
#   MIT License
#
#   Copyright (c) 2024, Mattias Aabmets
#
#   The contents of this file are subject to the terms and conditions defined in the License.
#   You may not use, modify, or distribute this file except in compliance with the License.
#
#   SPDX-License-Identifier: MIT
#
import pytest
import collections.abc as c
from src.aes_blake import AESBlake, BlockSize
from src.blake_keygen import BlakeKeyGen
from src.aes_block import AESBlock


@pytest.fixture(name="blocks_data", scope="function")
def fixture_blocks_data() -> list[bytes]:
	data1 = bytes([b for b in [0x1A, 0x2A, 0x3A, 0x4A] for _ in range(4)])
	data2 = bytes([b for b in [0x1B, 0x2B, 0x3B, 0x4B] for _ in range(4)])
	data3 = bytes([b for b in [0x1C, 0x2C, 0x3C, 0x4C] for _ in range(4)])
	data4 = bytes([b for b in [0x1D, 0x2D, 0x3D, 0x4D] for _ in range(4)])
	return [data1, data2, data3, data4]


@pytest.fixture(name="create_blocks", scope="function")
def fixture_create_blocks(blocks_data) -> c.Callable[[bytes, bytes, bytes], list[AESBlock]]:
	def closure(key=b'', nonce=b'', context=b'') -> list[AESBlock]:
		keygen = BlakeKeyGen(key, nonce, context)
		block1 = AESBlock(keygen, blocks_data[0], 0)
		block2 = AESBlock(keygen, blocks_data[1], 1)
		block3 = AESBlock(keygen, blocks_data[2], 2)
		block4 = AESBlock(keygen, blocks_data[3], 3)
		return [block1, block2, block3, block4]
	return closure


def test_exchange_columns_128(create_blocks, blocks_data):
	key, nonce, context = b'', b'', b''
	blocks = create_blocks(key, nonce, context)
	cipher = AESBlake(key, context, block_size=BlockSize.BITS_128)

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
	key, nonce, context = b'', b'', b''
	blocks = create_blocks(key, nonce, context)
	cipher = AESBlake(key, context, block_size=BlockSize.BITS_256)

	cipher.exchange_columns(blocks)
	assert bytes(blocks[0].state) == bytes([
		0x1A, 0x1A, 0x1A, 0x1A,  # 1A
		0x2B, 0x2B, 0x2B, 0x2B,  # 2B
		0x3A, 0x3A, 0x3A, 0x3A,  # 3A
		0x4B, 0x4B, 0x4B, 0x4B,  # 4B
	])
	assert bytes(blocks[1].state) == bytes([
		0x1B, 0x1B, 0x1B, 0x1B,  # 1B
		0x2A, 0x2A, 0x2A, 0x2A,  # 2A
		0x3B, 0x3B, 0x3B, 0x3B,  # 3B
		0x4A, 0x4A, 0x4A, 0x4A,  # 4A
	])
	assert bytes(blocks[2].state) == blocks_data[2]
	assert bytes(blocks[3].state) == blocks_data[3]

	cipher.exchange_columns(blocks, inverse=True)
	assert bytes(blocks[0].state) == blocks_data[0]
	assert bytes(blocks[1].state) == blocks_data[1]
	assert bytes(blocks[2].state) == blocks_data[2]
	assert bytes(blocks[3].state) == blocks_data[3]


def test_exchange_columns_384(create_blocks, blocks_data):
	key, nonce, context = b'', b'', b''
	blocks = create_blocks(key, nonce, context)
	cipher = AESBlake(key, context, block_size=BlockSize.BITS_384)

	cipher.exchange_columns(blocks)
	assert bytes(blocks[0].state) == bytes([
		0x1A, 0x1A, 0x1A, 0x1A,  # 1A
		0x2B, 0x2B, 0x2B, 0x2B,  # 2B
		0x3C, 0x3C, 0x3C, 0x3C,  # 3C
		0x4A, 0x4A, 0x4A, 0x4A,  # 4A
	])
	assert bytes(blocks[1].state) == bytes([
		0x1B, 0x1B, 0x1B, 0x1B,  # 1B
		0x2C, 0x2C, 0x2C, 0x2C,  # 2C
		0x3A, 0x3A, 0x3A, 0x3A,  # 3A
		0x4B, 0x4B, 0x4B, 0x4B,  # 4B
	])
	assert bytes(blocks[2].state) == bytes([
		0x1C, 0x1C, 0x1C, 0x1C,  # 1C
		0x2A, 0x2A, 0x2A, 0x2A,  # 2A
		0x3B, 0x3B, 0x3B, 0x3B,  # 3B
		0x4C, 0x4C, 0x4C, 0x4C,  # 4C
	])
	assert bytes(blocks[3].state) == blocks_data[3]

	cipher.exchange_columns(blocks, inverse=True)
	assert bytes(blocks[0].state) == blocks_data[0]
	assert bytes(blocks[1].state) == blocks_data[1]
	assert bytes(blocks[2].state) == blocks_data[2]
	assert bytes(blocks[3].state) == blocks_data[3]


def test_exchange_columns_512(create_blocks, blocks_data):
	key, nonce, context = b'', b'', b''
	blocks = create_blocks(key, nonce, context)
	cipher = AESBlake(key, context, block_size=BlockSize.BITS_512)

	cipher.exchange_columns(blocks)
	assert bytes(blocks[0].state) == bytes([
		0x1A, 0x1A, 0x1A, 0x1A,  # 1A
		0x2B, 0x2B, 0x2B, 0x2B,  # 2B
		0x3C, 0x3C, 0x3C, 0x3C,  # 3C
		0x4D, 0x4D, 0x4D, 0x4D,  # 4D
	])
	assert bytes(blocks[1].state) == bytes([
		0x1B, 0x1B, 0x1B, 0x1B,  # 1B
		0x2C, 0x2C, 0x2C, 0x2C,  # 2C
		0x3D, 0x3D, 0x3D, 0x3D,  # 3D
		0x4A, 0x4A, 0x4A, 0x4A,  # 4A
	])
	assert bytes(blocks[2].state) == bytes([
		0x1C, 0x1C, 0x1C, 0x1C,  # 1C
		0x2D, 0x2D, 0x2D, 0x2D,  # 2D
		0x3A, 0x3A, 0x3A, 0x3A,  # 3A
		0x4B, 0x4B, 0x4B, 0x4B,  # 4B
	])
	assert bytes(blocks[3].state) == bytes([
		0x1D, 0x1D, 0x1D, 0x1D,  # 1D
		0x2A, 0x2A, 0x2A, 0x2A,  # 2A
		0x3B, 0x3B, 0x3B, 0x3B,  # 3B
		0x4C, 0x4C, 0x4C, 0x4C,  # 4C
	])

	cipher.exchange_columns(blocks, inverse=True)
	assert bytes(blocks[0].state) == blocks_data[0]
	assert bytes(blocks[1].state) == blocks_data[1]
	assert bytes(blocks[2].state) == blocks_data[2]
	assert bytes(blocks[3].state) == blocks_data[3]
