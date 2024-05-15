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
from __future__ import annotations
from copy import deepcopy
from aes_cube.sbox import SBox
from aes_cube.uint import Uint32, Uint64


class BlakeKeyGen:
	vector: list[Uint32]
	ivs = (
		0x6A09E667, 0xF3BCC908, 0xBB67AE85, 0x84CAA73B,  # 0,  1,  2,  3
		0x3C6EF372, 0xFE94F82B, 0xA54FF53A, 0x5F1D36F1,  # 4,  5,  6,  7
		0x510E527F, 0xADE682D1, 0x9B05688C, 0x2B3E6C1F,  # 8,  9,  10, 11
		0x1F83D9AB, 0xFB41BD6B, 0x5BE0CD19, 0x137E2179,  # 12, 13, 14, 15
	)  # From SHA-512, split into 32-bit integers

	def mix(self, a: int, b: int, c: int, d: int, x: Uint32, y: Uint32) -> None:
		"""
		The G (mixing) function of the Blake hash algorithm.
		Note: Automatic mod 2**32 is applied for Uint32 arithmetic!
		"""
		vec = self.vector

		vec[a] = vec[a] + vec[b] + x
		vec[d] = (vec[d] ^ vec[a]) >> 16
		vec[c] = vec[c] + vec[d]
		vec[b] = (vec[b] ^ vec[c]) >> 12

		vec[a] = vec[a] + vec[b] + y
		vec[d] = (vec[d] ^ vec[a]) >> 8
		vec[c] = vec[c] + vec[d]
		vec[b] = (vec[b] ^ vec[c]) >> 7

	def compress(
			self,
			key: list[Uint32] = None,
			cl: Uint32 | None = None,  # counter low
			ch: Uint32 | None = None   # counter high
	) -> None:
		"""
		The E (compression) function of the Blake hash algorithm.
		Note: Only components essential to the current use case are retained.
		"""
		self.mix(0, 4, 8, 12, cl or key[0], ch or key[1])
		self.mix(1, 5, 9, 13, cl or key[2], ch or key[3])
		self.mix(2, 6, 10, 14, cl or key[4], ch or key[5])
		self.mix(3, 7, 11, 15, cl or key[6], ch or key[7])

		self.mix(0, 5, 10, 15, cl or key[8], ch or key[9])
		self.mix(1, 6, 11, 12, cl or key[10], ch or key[11])
		self.mix(2, 7, 8, 13, cl or key[12], ch or key[13])
		self.mix(3, 4, 9, 14, cl or key[14], ch or key[15])

	def __init__(self, key: bytes | bytearray = b'', salt: bytes | bytearray = b'') -> None:
		_key: list[Uint32] = self.to_uint_list(key)
		_salt: list[Uint32] = self.to_uint_list(salt)

		# initialize state vector
		self.vector = [
			_salt[i] ^ self.ivs[i]
			for i in range(16)
		]
		# compute initial 10 rounds
		for i in range(10):
			self.compress(_key)

		# initialize block counter from altered vector
		self.counter = Uint64.from_bytes(
			self.vector[4].to_bytes() +
			self.vector[5].to_bytes()
		).sub_bytes(SBox.ENC)

	@staticmethod
	def to_uint_list(source: bytes | bytearray) -> list[Uint32]:
		src_len = len(source)
		if src_len % 4 != 0 or src_len > 64:
			raise ValueError
		output: list[Uint32] = []
		for i in range(0, src_len, 4):
			output.append(Uint32.from_bytes(
				data=source[i:i + 4],
				byteorder="little"
			))
		while len(output) < 16:
			output.append(Uint32(0))
		return output

	def clone(self) -> BlakeKeyGen:
		return deepcopy(self)
