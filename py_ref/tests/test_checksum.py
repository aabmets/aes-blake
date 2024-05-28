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
from src.checksum import CheckSum
from src.uint import Uint8


__all__ = ["test_checksum"]


def test_checksum():
	chk = CheckSum()
	for obj in chk.state:
		assert isinstance(obj, Uint8)

	data1 = b'\x27' * 16
	data2 = b'\xEB' * 16
	data3 = b'\x9A' * 16
	data4 = b'\x5C' * 16

	chk.xor_with(data1)
	for i in range(0, 16):
		assert chk.state[i] == 0x27

	chk.xor_with(data2)
	for i in range(0, 16):
		assert chk.state[i] == 0xCC

	chk.xor_with(data3)
	for i in range(0, 16):
		assert chk.state[i] == 0x56

	chk.xor_with(data4)
	for i in range(0, 16):
		assert chk.state[i] == 0x0A

	assert chk.to_bytes() == b'\x0A' * 16
