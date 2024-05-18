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
import typing as t
from .uint import Uint8
from .blake_keygen import KeyGen
from .aes_sbox import SBox


Bytes = t.Union[bytes | bytearray]


class AESBlock:
	vector: list[Uint8]

	def __init__(self, blake: KeyGen, index: int, data: Bytes) -> None:
		self.blake = blake.clone()
		self.vector = [Uint8(b) for b in data]
		self.keys = self.precompute_keys(index)

	def precompute_keys(self, index: int) -> list[list[Uint8]]:
		self.blake.set_block_index(index)
		keys = []
		for _ in range(10):
			self.blake.compress("expand")
			key = self.blake.to_uint8_list()
			keys.append(key)
		self.blake.compress("finalize")
		key = self.blake.to_uint8_list()
		keys.append(key)
		return keys

	def encrypt_block(self) -> None:
		for i in range(10):
			self.sub_bytes(SBox.ENC)
			self.shift_rows()
			self.mix_columns()
			self.add_round_key(i)
		self.sub_bytes(SBox.ENC)
		self.shift_rows()
		self.add_round_key(-1)

	def decrypt_block(self) -> None:
		self.add_round_key(-1)
		self.inv_shift_rows()
		self.sub_bytes(SBox.DEC)
		for i in range(9, 0, -1):
			self.add_round_key(i)
			self.inv_mix_columns()
			self.inv_shift_rows()
			self.sub_bytes(SBox.DEC)
		self.add_round_key(0)

	def sub_bytes(self, sbox: SBox) -> None:
		for uint8 in self.vector:
			uint8.sub_bytes(sbox)

	def shift_rows(self) -> None:
		vec = self.vector
		vec[1], vec[5], vec[9], vec[13] = vec[5], vec[9], vec[13], vec[1]
		vec[2], vec[6], vec[10], vec[14] = vec[10], vec[14], vec[2], vec[6]
		vec[3], vec[7], vec[11], vec[15] = vec[15], vec[3], vec[7], vec[11]

	def inv_shift_rows(self) -> None:
		vec = self.vector
		vec[1], vec[5], vec[9], vec[13] = vec[13], vec[1], vec[5], vec[9]
		vec[2], vec[6], vec[10], vec[14] = vec[10], vec[14], vec[2], vec[6]
		vec[3], vec[7], vec[11], vec[15] = vec[7], vec[11], vec[15], vec[3]

	@staticmethod
	def xtime(a: Uint8) -> Uint8:
		x = (a.value << 1) & 0xFF
		y = -(a.value >> 7) & 0x1B
		return Uint8(x ^ y)

	def mix_single_column(self, a: int, b: int, c: int, d: int) -> None:
		vec = self.vector
		x = vec[a] ^ vec[b] ^ vec[c] ^ vec[d]
		y = vec[a].value
		vec[a] ^= x ^ self.xtime(vec[a] ^ vec[b])
		vec[b] ^= x ^ self.xtime(vec[b] ^ vec[c])
		vec[c] ^= x ^ self.xtime(vec[c] ^ vec[d])
		vec[d] ^= x ^ self.xtime(vec[d] ^ y)

	def mix_columns(self) -> None:
		for i in range(0, 16, 4):
			self.mix_single_column(i, i+1, i+2, i+3)

	def inv_mix_columns(self) -> None:
		vec = self.vector
		for i in range(0, 16, 4):
			m = vec[i] ^ vec[i + 2]
			n = vec[i + 1] ^ vec[i + 3]
			x = self.xtime(self.xtime(m))
			y = self.xtime(self.xtime(n))
			vec[i] ^= x
			vec[i + 1] ^= y
			vec[i + 2] ^= x
			vec[i + 3] ^= y
		self.mix_columns()

	def add_round_key(self, index: int) -> None:
		for i, uint8 in enumerate(self.keys[index]):
			self.vector[i] ^= uint8
