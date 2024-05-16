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
from .blake import BlakeKeyGen
from .uint import Uint8
from .sbox import SBox


Bytes = t.Union[bytes | bytearray]


class BlakeAES:
	def __init__(self, key: Bytes, nonce: Bytes) -> None:
		self.blake = BlakeKeyGen(key, nonce)

	def encrypt(self, plaintext: Bytes) -> bytes:
		return self._process(plaintext)

	def decrypt(self, ciphertext: Bytes) -> bytes:
		return self._process(ciphertext)

	def _process(self, plaintext: Bytes) -> bytes:
		counter, out = 0, []
		for i in range(0, len(plaintext), 16):
			block = CipherBlock(self.blake, counter)
			block.encrypt_block()
			ciphertext = self.bitmask(
				data=plaintext[i:i+16],
				mask=block.vector
			)
			out.append(ciphertext)
			counter += 1
		return b''.join(out)

	@staticmethod
	def bitmask(data: Bytes, mask: list[Uint8]) -> bytes:
		return bytes(x ^ y.value for x, y in zip(data, mask))


class CipherBlock:
	vector: list[Uint8]

	def __init__(self, blake: BlakeKeyGen, block_index: int) -> None:
		self.blake = blake.clone()
		self.blake.set_block_index(block_index)
		self.vector = self.blake.aes_iv

	def encrypt_block(self) -> None:
		for i in range(10):
			self.sub_bytes()
			self.shift_rows()
			self.mix_columns()
			self.add_round_key(i)

	def sub_bytes(self):
		for v in self.vector:
			v.sub_bytes(SBox.ENC)

	def shift_rows(self):
		vec = self.vector
		vec[1], vec[5], vec[9], vec[13] = vec[5], vec[9], vec[13], vec[1]
		vec[2], vec[6], vec[10], vec[14] = vec[10], vec[14], vec[2], vec[6]
		vec[3], vec[7], vec[11], vec[15] = vec[15], vec[3], vec[7], vec[11]

	@staticmethod
	def xtime(a: Uint8) -> Uint8:
		x = (a.value << 1) & 0xFF
		y = -(a.value >> 7) & 0x1B
		return Uint8(x ^ y)

	def mix_single_column(self, a: int, b: int, c: int, d: int):
		vec = self.vector
		x = vec[a] ^ vec[b] ^ vec[c] ^ vec[d]
		y = vec[a].value
		vec[a] ^= x ^ self.xtime(vec[a] ^ vec[b])
		vec[b] ^= x ^ self.xtime(vec[b] ^ vec[c])
		vec[c] ^= x ^ self.xtime(vec[c] ^ vec[d])
		vec[d] ^= x ^ self.xtime(vec[d] ^ y)

	def mix_columns(self):
		for i in range(0, 16, 4):
			self.mix_single_column(i, i+1, i+2, i+3)

	def add_round_key(self, i: int) -> None:
		self.blake.compress("expand" if i < 9 else "finalize")
		for i, v in enumerate(self.blake.aes_vector):
			self.vector[i] ^= v
