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
from src.blake_keygen import BlakeKeyGen
from src.uint import Uint32, Uint64


ONE, ZERO = Uint32(1), Uint32(0)


@pytest.fixture(name="blank_keygen", scope="module")
def fixture_blank_keygen():
	keygen = BlakeKeyGen()
	keygen.vector = [Uint32(0)] * 16
	keygen.block_index = Uint64(0)
	return keygen


def test_mix_method(blank_keygen):
	keygen = blank_keygen.clone()

	keygen.mix(0, 4, 8, 12, ONE, ZERO)
	assert keygen.vector[0].value == 0x00000011   # 00000000 00000000 00000000 00010001
	assert keygen.vector[4].value == 0x20220202   # 00100000 00100010 00000010 00000010
	assert keygen.vector[8].value == 0x11010100   # 00010001 00000001 00000001 00000000
	assert keygen.vector[12].value == 0x11000100  # 00010001 00000000 00000001 00000000

	keygen.mix(0, 4, 8, 12, ONE, ZERO)
	assert keygen.vector[0].value == 0x22254587   # 00100010 00100101 01000101 10000111
	assert keygen.vector[4].value == 0xCB766A41   # 11001011 01110110 01101010 01000001
	assert keygen.vector[8].value == 0xB9366396   # 10111001 00110110 01100011 10010110
	assert keygen.vector[12].value == 0xA5213174  # 10100101 00100001 00110001 01110100

	for i in [1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15]:
		assert keygen.vector[i].value == 0


def test_compress_extract(blank_keygen):
	keygen = blank_keygen.clone()
	key = [Uint32(0)] * 16
	key[0] = Uint32(1)

	keygen.compress("extract", key)
	assert keygen.vector[0].value == 0x00000121  # 00000000 00000000 00000001 00100001
	assert keygen.vector[1].value == 0x10001001  # 00010000 00000000 00010000 00000001
	assert keygen.vector[2].value == 0x10011010  # 00010000 00000001 00010000 00010000
	assert keygen.vector[3].value == 0x42242404  # 01000010 00100100 00100100 00000100

	keygen.compress("extract", key)
	assert keygen.vector[0].value == 0xCA362DD6  # 11001010 00110110 00101101 11010110
	assert keygen.vector[1].value == 0x137F4EC0  # 00010011 01111111 01001110 11000000
	assert keygen.vector[2].value == 0xC494A2BB  # 11000100 10010100 10100010 10111011
	assert keygen.vector[3].value == 0x646EF8F0  # 01100100 01101110 11111000 11110000

	for i in range(4, 16):
		assert keygen.vector[i].value != 0


def test_compress_expand(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_block_index(1)

	for i in range(4, 16):
		assert keygen.vector[i].value == 0

	keygen.compress("expand")
	assert keygen.vector[0].value == 0x22552527  # 00100010 01010101 00100101 00100111
	assert keygen.vector[1].value == 0x23A56143  # 00100011 10100101 01100001 01000011
	assert keygen.vector[2].value == 0x22251F56  # 00100010 00100101 00011111 01010110
	assert keygen.vector[3].value == 0x42254587  # 01000010 00100101 01000101 10000111


def test_compress_finalize(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_block_index(1)

	for i in range(4, 16):
		assert keygen.vector[i].value == 0

	keygen.compress("finalize")
	assert keygen.vector[0].value == 0x42254587  # 01000010 00100101 01000101 10000111
	assert keygen.vector[1].value == 0x22552527  # 00100010 01010101 00100101 00100111
	assert keygen.vector[2].value == 0x23A56143  # 00100011 10100101 01100001 01000011
	assert keygen.vector[3].value == 0x22251F56  # 00100010 00100101 00011111 01010110


def test_flip_bits(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.vector[0] = Uint32(0x0000ABCD)        # 00000000 00000000 10101011 11001101
	keygen.flip_bits(0)
	assert keygen.vector[0].value == 0xFFFF5432  # 11111111 11111111 01010100 00110010


def test_separate_domains_extract(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.block_index = Uint64(0xAABBCCDDEEFFAABB)

	bil, bih = keygen.separate_domains("extract")
	assert bil is None and bih is None
	assert keygen.vector[14].value == 0
	assert keygen.vector[15].value == 0


def test_separate_domains_expand(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.block_index = Uint64(0xAABBCCDDEEFFAABB)

	keygen.set_block_index(1)
	bil, bih = keygen.separate_domains("expand")
	assert bil.value == 0xEEFFAABC
	assert bih.value == 0xAABBCCDD
	assert keygen.vector[14].value == 0xFFFFFFFF
	assert keygen.vector[15].value == 0


def test_separate_domains_finalize(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.block_index = Uint64(0xAABBCCDDEEFFAABB)

	keygen.set_block_index(0x100000000)
	bil, bih = keygen.separate_domains("finalize")
	assert bil.value == 0xEEFFAABB
	assert bih.value == 0xAABBCCDE
	assert keygen.vector[14].value == 0
	assert keygen.vector[15].value == 0xFFFFFFFF


def test_to_uint8_list(blank_keygen):
	keygen = blank_keygen.clone()
	for i in range(4, 9):
		keygen.vector[i] = Uint32(0xAABBCCDD)
	vec = keygen.to_uint8_list()
	for i in [0, 4, 8, 12]:
		assert vec[i].value == 0xAA
	for i in [1, 5, 9, 13]:
		assert vec[i].value == 0xBB
	for i in [2, 6, 10, 14]:
		assert vec[i].value == 0xCC
	for i in [3, 7, 11, 15]:
		assert vec[i].value == 0xDD


def test_uint32_list_from_bytes():
	uint32_str = b"\xAA\xBB\xCC\xDD"
	uint = Uint32.from_bytes(uint32_str, byteorder="little")
	assert uint.value == 0xDDCCBBAA

	res = BlakeKeyGen.uint32_list_from_bytes(uint32_str * 9)
	assert len(res) == 16

	for i in range(16):
		assert isinstance(res[i], Uint32)
		if i < 9:
			assert res[i].value == 0xDDCCBBAA
		else:
			assert res[i].value == 0


def test_normal_init():
	keygen = BlakeKeyGen(key=b'', nonce=b'')
	expected_vector = [
		0x8116C17C, 0xC7D2B9EE, 0x0B565DD4, 0x18C51225,
		0xAB24CCB6, 0x24A50A4A, 0x4F6BA54D, 0xA405D678,
		0xEF307156, 0x617539E3, 0x5AED265D, 0x07C4C974,
		0xAC5F589B, 0x07431860, 0xEC16EDAC, 0xCA051126
	]
	for i in range(16):
		assert keygen.vector[i].value == expected_vector[i]
	assert keygen.block_index.value == 0x91CF6A14C51AADD0


def test_xor_with(blank_keygen):
	keygen = blank_keygen.clone()
	for uint32 in keygen.vector:
		assert uint32.value == 0

	keygen.xor_with([0x1234ABCD] * 16)
	for i, uint32 in enumerate(keygen.vector):
		assert uint32.value == 0x1234ABCD

	keygen.xor_with([0xFEDC9876] * 16)
	for i, uint32 in enumerate(keygen.vector):
		assert uint32.value == 0xECE833BB
