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
from typing import cast
import aes_cube.types as t
from aes_cube.sbox import SBox


def test_uint_attrs():
	for c in [t.Uint8, t.Uint32]:
		v = c()
		assert hasattr(v, "bit_count")
		assert hasattr(v, "binary_bytes")
		assert hasattr(v, "sub_bytes")
		assert hasattr(v, "from_bytes")
		assert hasattr(v, "__init__")
		assert hasattr(v, "__add__")
		assert hasattr(v, "__and__")
		assert hasattr(v, "__xor__")
		assert hasattr(v, "__rshift__")
		assert hasattr(v, "__lshift__")
		assert hasattr(v, "__int__")
		assert hasattr(v, "__str__")
		assert hasattr(v, "__index__")


def test_uint8():
	with pytest.raises(TypeError):
		t.Uint8(cast(int, "asdfg"))

	v0 = t.Uint8()
	assert int(v0) == 0
	assert v0.bit_count == 8
	assert v0.binary_bytes == ["00000000"]

	v1 = t.Uint8(123)
	assert int(v1) == 123
	assert v1.binary_bytes == ["01111011"]

	v2 = t.Uint8(234)
	assert int(v2) == 234
	assert v2.binary_bytes == ["11101010"]

	v3 = v1 + v2
	assert int(v3) == 101
	assert v3.binary_bytes == ["01100101"]

	v3 = v1 & v2
	assert int(v3) == 106
	assert v3.binary_bytes == ["01101010"]

	v3 = v1 ^ v2
	assert int(v3) == 145
	assert v3.binary_bytes == ["10010001"]

	v3 = v1 >> 1
	assert int(v3) == 189
	assert v3.binary_bytes == ["10111101"]

	v3 = v1 << 1
	assert int(v3) == 246
	assert v3.binary_bytes == ["11110110"]

	v3 = v1 >> (v1.bit_count // 2)
	assert int(v3) == 183
	assert v3.binary_bytes == ["10110111"]

	v2.sub_bytes(SBox.ENC)
	assert int(v2) == 135
	assert v2.binary_bytes == ["10000111"]

	v2.sub_bytes(SBox.DEC)
	assert int(v2) == 234
	assert v2.binary_bytes == ["11101010"]


def test_uint32():
	with pytest.raises(TypeError):
		t.Uint32(cast(int, "asdfg"))

	v0 = t.Uint32()
	assert int(v0) == 0
	assert v0.bit_count == 32
	assert v0.binary_bytes == ["00000000", "00000000", "00000000", "00000000"]

	v1 = t.Uint32(11_22_33_44_55)
	assert int(v1) == 11_22_33_44_55
	assert v1.binary_bytes == ["01000010", "11100101", "01110110", "11110111"]

	v2 = t.Uint32(33_44_55_66_77)
	assert int(v2) == 33_44_55_66_77
	assert v2.binary_bytes == ["11000111", "01011001", "11100010", "10000101"]

	v3 = v1 + v2
	assert int(v3) == 171_923_836
	assert v3.binary_bytes == ["00001010", "00111111", "01011001", "01111100"]

	v3 = v1 & v2
	assert int(v3) == 1_111_581_317
	assert v3.binary_bytes == ["01000010", "01000001", "01100010", "10000101"]

	v3 = v1 ^ v2
	assert int(v3) == 2_243_728_498
	assert v3.binary_bytes == ["10000101", "10111100", "10010100", "01110010"]

	v3 = v1 >> 1
	assert int(v3) == 2_708_650_875
	assert v3.binary_bytes == ["10100001", "01110010", "10111011", "01111011"]

	v3 = v1 << 1
	assert int(v3) == 2_244_668_910
	assert v3.binary_bytes == ["10000101", "11001010", "11101101", "11101110"]

	v3 = v1 << (v1.bit_count // 2)
	assert int(v3) == 1_995_916_005
	assert v3.binary_bytes == ["01110110", "11110111", "01000010", "11100101"]

	v2.sub_bytes(SBox.ENC)
	assert int(v2) == 3_335_231_639
	assert v2.binary_bytes == ['11000110', '11001011', '10011000', '10010111']

	v2.sub_bytes(SBox.DEC)
	assert int(v2) == 33_44_55_66_77
	assert v2.binary_bytes == ["11000111", "01011001", "11100010", "10000101"]


def test_from_bytes():
	with pytest.raises(TypeError):
		t.Uint8.from_bytes(cast(bytes, 123))
	with pytest.raises(TypeError):
		t.Uint32.from_bytes(cast(bytes, 11_22_33_44_55))

	v = t.Uint8.from_bytes(b"\x7B", byteorder="big")
	assert int(v) == 123
	v = t.Uint8.from_bytes(b"\x7B", byteorder="little")
	assert int(v) == 123

	v = t.Uint32.from_bytes(b"\x42\xE5\x76\xF7", byteorder="big")
	assert int(v) == 11_22_33_44_55
	v = t.Uint32.from_bytes(b"\x42\xE5\x76\xF7", byteorder="little")
	assert int(v) == 41_51_76_42_90
