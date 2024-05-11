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
from aes_cube.sbox import SBox


@pytest.fixture(name="sbox", scope="module")
def fixture_sbox():
	sbox = [0] * 256
	for i in range(256):
		# Get multiplicative inverse in GF(2^8), except for 0 which maps to 0
		inverse = inv(i)
		# Apply the affine transformation
		sbox[i] = (
			(inverse << 1) ^ (inverse << 2) ^ (inverse << 3) ^
			(inverse << 4) ^ (inverse >> 4) ^ (inverse >> 5) ^
			(inverse >> 6) ^ (inverse >> 7) ^ inverse ^ 0x63
		) & 0xff
	return sbox


def multiply(x, y):
	result = 0
	for bit in range(8):
		if y & 1:
			result ^= x
		high_bit_set = x & 0x80
		x <<= 1
		if high_bit_set:
			x ^= 0x1b  # Polynomial in GF(2^8) is x^8 + x^4 + x^3 + x + 1
		y >>= 1
	return result % 256


def inv(x):
	# Return the multiplicative inverse of x in GF(2^8)
	# Using brute force method since it's simple
	# and always correct for this context
	if x == 0:
		return 0
	for i in range(1, 256):
		if multiply(i, x) == 1:
			return i
	return None


def compute_inverse_sbox(sbox):
	inverse_sbox = [0] * 256
	for i in range(256):
		inverse_sbox[sbox[i]] = i
	return inverse_sbox


def test_sbox(sbox):
	for row in range(16):
		for col in range(16):
			index = row * 16 + col
			computed_value = sbox[index]
			hardcoded_value = SBox.ENC.value[index]
			assert computed_value == hardcoded_value


def test_inv_sbox(sbox):
	inv_sbox = compute_inverse_sbox(sbox)
	for row in range(16):
		for col in range(16):
			index = row * 16 + col
			computed_value = inv_sbox[index]
			hardcoded_value = SBox.DEC.value[index]
			assert computed_value == hardcoded_value
