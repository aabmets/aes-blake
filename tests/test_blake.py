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
from aes_cube.uint import Uint32


def test_convert_bytes():
	uint32_str = b"\x01\x02\x03\x04"
	uint = Uint32.from_bytes(uint32_str, byteorder="little")
	assert uint.value == 67_305_985

	res = BlakeKeyGen.to_uint_list(uint32_str * 10)
	assert len(res) == 16

	for i in range(16):
		assert isinstance(res[i], Uint32)
		if i < 10:
			assert res[i].value == 67_305_985
		else:
			assert res[i].value == 0
