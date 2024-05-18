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
from aes_cube.checksum import CheckSum
from aes_cube.uint import Uint8, Uint32


__all__ = ["test_checksum"]


def test_checksum():
	chk = CheckSum()
	for obj in chk.checksum:
		assert isinstance(obj, Uint8)

	data1 = b'\x27' * 16
	data2 = b'\xEB' * 16
	data3 = b'\x9A' * 16
	data4 = b'\x5C' * 16

	chk.xor_with(data1)
	for i in range(0, 16):
		assert chk.checksum[i] == 0x27
	for i in range(16, 32):
		assert chk.checksum[i] == 0

	chk.xor_with(data2)
	for i in range(0, 16):
		assert chk.checksum[i] == 0x27
	for i in range(16, 32):
		assert chk.checksum[i] == 0xEB

	chk.xor_with(data3)
	for i in range(0, 16):
		assert chk.checksum[i] == 0xBD  # 0x27 ^ 0x9A
	for i in range(16, 32):
		assert chk.checksum[i] == 0xEB

	chk.xor_with(data4)
	for i in range(0, 16):
		assert chk.checksum[i] == 0xBD
	for i in range(16, 32):
		assert chk.checksum[i] == 0xB7  # 0xEB ^ 0x5C

	vector = chk.to_uint32_list()
	assert len(vector) == 8
	for obj in vector:
		assert isinstance(obj, Uint32)
	for i in range(0, 4):
		assert vector[i].value == 0xBDBDBDBD
	for i in range(4, 8):
		assert vector[i].value == 0xB7B7B7B7
