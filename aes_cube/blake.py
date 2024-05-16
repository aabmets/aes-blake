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
import typing as t
from copy import deepcopy
from aes_cube.sbox import SBox
from aes_cube.uint import Uint8, Uint32, Uint64


KDFMode = t.Literal["extract", "expand", "finalize"]
Bytes = t.Union[bytes | bytearray]


class BlakeKeyGen:
	vector: list[Uint32]
	ivs = (
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,  # 08, 09, 10, 11
		0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,  # 12, 13, 14, 15
	)

	def mix(self, a: int, b: int, c: int, d: int, x: Uint32, y: Uint32) -> None:
		"""
		The G (mixing) function of the Blake hash algorithm.
		Note: Automatic mod 2**32 is applied for Uint32 arithmetic and
		<<, >> operators rotate with circular shift.
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

	def compress(self, mode: KDFMode, key: list[Uint32] = None) -> None:
		"""
		The E (compression) function of the Blake hash algorithm with minor alterations.
		Note: Only components essential for the KDF use case have been retained.

		If mode == "extract", then BIL and BIH are None, otherwise they are Uint32.
		If mode == "expand", then vector[14] bits have been flipped.
		If mode == "finalize", then vector[15] bits have been flipped.
		"""
		bil, bih = self.separate_domains(mode)

		self.mix(0, 4, 8, 12, bil or key[0], bih or key[1])
		self.mix(1, 5, 9, 13, bil or key[2], bih or key[3])
		self.mix(2, 6, 10, 14, bil or key[4], bih or key[5])
		self.mix(3, 7, 11, 15, bil or key[6], bih or key[7])

		self.mix(0, 5, 10, 15, bil or key[8], bih or key[9])
		self.mix(1, 6, 11, 12, bil or key[10], bih or key[11])
		self.mix(2, 7, 8, 13, bil or key[12], bih or key[13])
		self.mix(3, 4, 9, 14, bil or key[14], bih or key[15])

	def __init__(self, key: Bytes = b'', nonce: Bytes = b'') -> None:
		if len(key) > 64:
			raise ValueError("Key length must be less than or equal to 64 bytes")
		if len(nonce) > 32:
			raise ValueError("Nonce length must be less than or equal to 32 bytes")

		# Initialize state vector
		self.vector = self.to_uint_list(nonce)
		for i in range(8):
			self.vector[i+8] = Uint32(self.ivs[i])

		# Compute initial 10 rounds
		_key = self.to_uint_list(key)
		for i in range(10):
			self.compress(mode="extract", key=_key)

		# Initialize block index from altered vector
		self.block_index = Uint64.from_bytes(
			self.vector[12].to_bytes() +
			self.vector[13].to_bytes()
		).sub_bytes(SBox.ENC)

		# Obtain AES IV from altered vector
		self.aes_iv: list[Uint8] = self.aes_vector

	@staticmethod
	def to_uint_list(source: Bytes) -> list[Uint32]:
		s_len = len(source)
		count = 4 - (s_len % 4)
		source += b'\x00' * count
		output: list[Uint32] = []
		for i in range(0, s_len, 4):
			output.append(Uint32.from_bytes(
				data=source[i:i + 4],
				byteorder="little"
			))
		while len(output) < 16:
			output.append(Uint32(0))
		return output

	def flip_bits(self, index: int):
		uint32 = self.vector[index]
		flipped = uint32 ^ uint32.max_value
		self.vector[index] = flipped

	def separate_domains(self, mode: str) -> tuple[Uint32 | None, Uint32 | None]:
		bil = None  # block index, low 32 bytes
		bih = None  # block index, high 32 bytes
		match mode:
			case "extract":
				return bil, bih
			case "expand":
				self.flip_bits(14)
			case "finalize":
				self.flip_bits(15)

		bib = self.block_index.to_bytes()
		bil = Uint32.from_bytes(bib[4:])
		bih = Uint32.from_bytes(bib[:4])
		return bil, bih

	def set_block_index(self, value: int):
		self.block_index += value

	@property
	def aes_vector(self) -> list[Uint8]:
		out = []
		for uint32 in self.vector[4:8]:
			for b in uint32.to_bytes():
				out.append(Uint8(b))
		return out

	def clone(self) -> BlakeKeyGen:
		return deepcopy(self)
