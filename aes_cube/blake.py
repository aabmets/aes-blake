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
from aes_cube.uint import Uint32


class BlakeKeyGen:
	vector: list[Uint32]
	ivs = (
		Uint32(0x6A09E667), Uint32(0xF3BCC908), Uint32(0xBB67AE85), Uint32(0x84CAA73B),  # 0,  1,  2,  3
		Uint32(0x3C6EF372), Uint32(0xFE94F82B), Uint32(0xA54FF53A), Uint32(0x5F1D36F1),  # 4,  5,  6,  7
		Uint32(0x510E527F), Uint32(0xADE682D1), Uint32(0x9B05688C), Uint32(0x2B3E6C1F),  # 8,  9,  10, 11
		Uint32(0x1F83D9AB), Uint32(0xFB41BD6B), Uint32(0x5BE0CD19), Uint32(0x137E2179),  # 12, 13, 14, 15
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

	def compress(self, data: list[Uint32]) -> None:
		"""
		The E (compression) function of the Blake hash algorithm.
		Note: Only components essential to the current use case are retained.
		"""
		self.mix(0, 4, 8, 12, data[0], data[1])
		self.mix(1, 5, 9, 13, data[2], data[3])
		self.mix(2, 6, 10, 14, data[4], data[5])
		self.mix(3, 7, 11, 15, data[6], data[7])

		self.mix(0, 5, 10, 15, data[8], data[9])
		self.mix(1, 6, 11, 12, data[10], data[11])
		self.mix(2, 7, 8, 13, data[12], data[13])
		self.mix(3, 4, 9, 14, data[14], data[15])

	def __init__(self, key: bytes | bytearray = b'', salt: bytes | bytearray = b'') -> None:
		key_ints: list[Uint32] = self.convert_bytes(key)
		salt_ints: list[Uint32] = self.convert_bytes(salt)

		# initialize state vector
		self.vector = [
			self.ivs[i] ^ salt_ints[i]
			for i in range(16)
		]
		# compute initial 10 rounds
		for i in range(10):
			self.compress(key_ints)

	@staticmethod
	def convert_bytes(source: bytes | bytearray) -> list[Uint32]:
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
			output.append(Uint32())
		return output
