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
import typing as t
from src.uint import BaseUint, Uint8, Uint32, Uint64


__all__ = [
	"test_uint_inheritance",
	"test_uint8",
	"test_uint32",
	"test_uint64",
	"test_to_bytes"
]


def test_uint_inheritance():
	for uint_type in [Uint8, Uint32, Uint64]:
		uint = uint_type()
		assert isinstance(uint, BaseUint)
		assert hasattr(uint, "bit_count")
		assert isinstance(uint.bit_count, int)
		assert hasattr(uint, "max_value")
		assert isinstance(uint.max_value, int)


def test_uint8():
	with pytest.raises(TypeError):
		Uint8(t.cast(int, "asdfg"))

	v0 = Uint8()
	v1 = Uint8(0xAA)
	v2 = Uint8(0xCC)

	assert v0.bit_count == 8
	assert v0.max_value == 0xFF

	assert v0.value == 0
	assert v1.value == 0xAA
	assert v2.value == 0xCC

	assert (-v1).value == 0x56
	assert (-v2).value == 0x34

	assert (v1 + v2).value == 0x76  # mod 2**8
	assert (v1 - v2).value == 0xDE  # mod 2**8

	assert (v1 & v2).value == 0x88
	assert (v1 | v2).value == 0xEE
	assert (v1 ^ v2).value == 0x66

	assert (v1 == v2) is False
	assert (v1 != v2) is True
	assert (v1 > v2) is False
	assert (v1 < v2) is True
	assert (v1 >= v2) is False
	assert (v1 <= v2) is True

	assert (v1 >> 1).value == 0x55  # rotate right by 1 bit
	assert (v1 << 1).value == 0x55  # rotate left by 1 bit
	assert (v1 >> 4).value == 0xAA  # switch halves


def test_uint32():
	with pytest.raises(TypeError):
		Uint32(t.cast(int, "asdfg"))

	v0 = Uint32()
	v1 = Uint32(0xAABBCCDD)
	v2 = Uint32(0xCCDDEEFF)

	assert v0.bit_count == 32
	assert v0.max_value == 0xFFFFFFFF

	assert v0.value == 0
	assert v1.value == 0xAABBCCDD
	assert v2.value == 0xCCDDEEFF

	assert (-v1).value == 0x00000023
	assert (-v2).value == 0x00000001

	assert (v1 + v2).value == 0x7799BBDC  # mod 2**32
	assert (v1 - v2).value == 0xDDDDDDDE  # mod 2**32

	assert (v1 & v2).value == 0x8899CCDD
	assert (v1 | v2).value == 0xEEFFEEFF
	assert (v1 ^ v2).value == 0x66662222

	assert (v1 == v2) is False
	assert (v1 != v2) is True
	assert (v1 > v2) is False
	assert (v1 < v2) is True
	assert (v1 >= v2) is False
	assert (v1 <= v2) is True

	assert (v1 >> 1).value == 0xD55DE66E   # rotate right by 1 bit
	assert (v1 << 1).value == 0x557799BB   # rotate left by 1 bit
	assert (v1 >> 16).value == 0xCCDDAABB  # switch halves


def test_uint64():
	with pytest.raises(TypeError):
		Uint64(t.cast(int, "asdfg"))

	v0 = Uint64()
	v1 = Uint64(0xAABBCCDDEEFFAABB)
	v2 = Uint64(0xCCDDEEFFAABBCCDD)

	assert v0.bit_count == 64
	assert v0.max_value == 0xFFFFFFFFFFFFFFFF

	assert v0.value == 0
	assert v1.value == 0xAABBCCDDEEFFAABB
	assert v2.value == 0xCCDDEEFFAABBCCDD

	assert (-v1).value == 0x0000000000000045
	assert (-v2).value == 0x0000000000000023

	assert (v1 + v2).value == 0x7799BBDD99BB7798  # mod 2**64
	assert (v1 - v2).value == 0xDDDDDDDE4443DDDE  # mod 2**64

	assert (v1 & v2).value == 0x8899CCDDAABB8899
	assert (v1 | v2).value == 0xEEFFEEFFEEFFEEFF
	assert (v1 ^ v2).value == 0x6666222244446666

	assert (v1 == v2) is False
	assert (v1 != v2) is True
	assert (v1 > v2) is False
	assert (v1 < v2) is True
	assert (v1 >= v2) is False
	assert (v1 <= v2) is True

	assert (v1 >> 1).value == 0xD55DE66EF77FD55D   # rotate right by 1 bit
	assert (v1 << 1).value == 0x557799BBDDFF5577   # rotate left by 1 bit
	assert (v1 >> 32).value == 0xEEFFAABBAABBCCDD  # switch halves


def test_to_bytes():
	byte_str = Uint8(0xAA).to_bytes(byteorder="big")
	assert byte_str == b"\xAA"

	byte_str = Uint8(0xAA).to_bytes(byteorder="little")
	assert byte_str == b"\xAA"

	byte_str = Uint32(0xAABBCCDD).to_bytes(byteorder="big")
	assert byte_str == b"\xAA\xBB\xCC\xDD"

	byte_str = Uint32(0xAABBCCDD).to_bytes(byteorder="little")
	assert byte_str == b"\xDD\xCC\xBB\xAA"

	byte_str = Uint64(0xAABBCCDDEEFFAABB).to_bytes(byteorder="big")
	assert byte_str == b"\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB"

	byte_str = Uint64(0xAABBCCDDEEFFAABB).to_bytes(byteorder="little")
	assert byte_str == b"\xBB\xAA\xFF\xEE\xDD\xCC\xBB\xAA"


def test_from_bytes():
	uint = Uint8.from_bytes(b"\xAA", byteorder="big")
	assert uint.value == 0xAA

	uint = Uint8.from_bytes(b"\xAA", byteorder="little")
	assert uint.value == 0xAA

	uint = Uint32.from_bytes(b"\xAA\xBB\xCC\xDD", byteorder="big")
	assert uint.value == 0xAABBCCDD

	uint = Uint32.from_bytes(b"\xAA\xBB\xCC\xDD", byteorder="little")
	assert uint.value == 0xDDCCBBAA

	uint = Uint64.from_bytes(b"\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB", byteorder="big")
	assert uint.value == 0xAABBCCDDEEFFAABB

	uint = Uint64.from_bytes(b"\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB", byteorder="little")
	assert uint.value == 0xBBAAFFEEDDCCBBAA
