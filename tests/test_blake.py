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
from aes_cube.blake import BlakeKeyGen


def test_bytes_to_int_list():
	uint32_str = b"\x01\x02\x03\x04"
	int_value = int.from_bytes(uint32_str, byteorder="little")
	assert int_value == 67_305_985

	res = BlakeKeyGen.bytes_to_int_list(uint32_str * 10)
	assert len(res) == 16

	for i in range(16):
		if i < 10:
			assert res[i] == 67_305_985
		else:
			assert res[i] == 0
