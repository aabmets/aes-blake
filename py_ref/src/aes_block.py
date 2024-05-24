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
from .uint import Uint8
from .aes_sbox import SBox
from .blake_keygen import BlakeKeyGen
from .uint import IterNum


__all__ = ["AESBlock"]


class AESBlock:
	def __init__(self, keygen: BlakeKeyGen, data: IterNum, counter: int) -> None:
		self.state = [Uint8(b) for b in data]
		self.keys = []
		for chunk in keygen.clone().derive_keys(counter):
			key = []
			for uint32 in chunk:
				for byte in uint32.to_bytes():
					key.append(Uint8(byte))
			self.keys.append(key)

	def encrypt_block(self) -> None:
		self.add_round_key(0)
		for i in range(1, 10):
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

	@staticmethod
	def xtime(a: Uint8) -> Uint8:
		x = (a.value << 1) & 0xFF
		y = -(a.value >> 7) & 0x1B
		return Uint8(x ^ y)

	def mix_single_column(self, a: int, b: int, c: int, d: int) -> None:
		s = self.state
		x = s[a] ^ s[b] ^ s[c] ^ s[d]
		y = s[a].value
		s[a] ^= x ^ self.xtime(s[a] ^ s[b])
		s[b] ^= x ^ self.xtime(s[b] ^ s[c])
		s[c] ^= x ^ self.xtime(s[c] ^ s[d])
		s[d] ^= x ^ self.xtime(s[d] ^ y)

	def mix_columns(self) -> None:
		for i in range(0, 16, 4):
			self.mix_single_column(i, i+1, i+2, i+3)

	def inv_mix_columns(self) -> None:
		s = self.state
		for i in range(0, 16, 4):
			m = s[i] ^ s[i + 2]
			n = s[i + 1] ^ s[i + 3]
			x = self.xtime(self.xtime(m))
			y = self.xtime(self.xtime(n))
			s[i] ^= x
			s[i + 1] ^= y
			s[i + 2] ^= x
			s[i + 3] ^= y
		self.mix_columns()

	def shift_rows(self) -> None:
		s = self.state
		s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
		s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
		s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]

	def inv_shift_rows(self) -> None:
		s = self.state
		s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
		s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
		s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]

	def add_round_key(self, index: int) -> None:
		for i, uint8 in enumerate(self.keys[index]):
			self.state[i] ^= uint8

	def sub_bytes(self, sbox: SBox) -> None:
		for uint8 in self.state:
			uint8.value = sbox.value[uint8.value]
