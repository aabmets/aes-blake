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
from enum import Enum
from copy import deepcopy
from .uint import Uint32, Uint64
from . import utils


class KDFDomain(Enum):
	DIGEST_CTX = 0x20  # 0010 0000
	DERIVE_KEY = 0x40  # 0100 0000
	LAST_ROUND = 0x80  # 1000 0000


class BlakeKeyGen:
	state: list[Uint32]
	ivs = (
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,  # 08, 09, 10, 11
		0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,  # 12, 13, 14, 15
	)  # From BLAKE3, which in turn took them from SHA-256

	def mix(self, a: int, b: int, c: int, d: int, mx: Uint32, my: Uint32) -> None:
		vec = self.state
		# first mixing
		vec[a] = vec[a] + vec[b] + mx
		vec[d] = (vec[d] ^ vec[a]) >> 16
		vec[c] = vec[c] + vec[d]
		vec[b] = (vec[b] ^ vec[c]) >> 12
		# second mixing
		vec[a] = vec[a] + vec[b] + my
		vec[d] = (vec[d] ^ vec[a]) >> 8
		vec[c] = vec[c] + vec[d]
		vec[b] = (vec[b] ^ vec[c]) >> 7

	def mix_into_state(self, m: list[Uint32]) -> None:
		# columnar mixing
		self.mix(0, 4, 8, 12, m[0], m[1])
		self.mix(1, 5, 9, 13, m[2], m[3])
		self.mix(2, 6, 10, 14, m[4], m[5])
		self.mix(3, 7, 11, 15, m[6], m[7])
		# diagonal mixing
		self.mix(0, 5, 10, 15, m[8], m[9])
		self.mix(1, 6, 11, 12, m[10], m[11])
		self.mix(2, 7, 8, 13, m[12], m[13])
		self.mix(3, 4, 9, 14, m[14], m[15])

	@staticmethod
	def permute(m: list[Uint32]) -> list[Uint32]:
		output = []
		for i in [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]:
			output.append(m[i])
		return output

	def set_params(self, domain: KDFDomain = None, block_index: int = None) -> None:
		if domain is not None:
			for i in range(8, 12):
				self.state[i] ^= domain.value
		if block_index is not None:
			bcb = (self.block_index_base + block_index).to_bytes()
			bc_low = Uint32.from_bytes(bcb[4:], byteorder="little")
			bc_high = Uint32.from_bytes(bcb[:4], byteorder="little")
			for i in range(4):
				self.state[i] ^= bc_low + i
				self.state[i + 12] ^= bc_high

	def __init__(self, key: bytes, nonce: bytes, context: bytes) -> None:
		self.key = utils.bytes_to_uint32_vector(key, size=16)
		self.state = utils.bytes_to_uint32_vector(nonce, size=16)
		self.block_index_base = self.compute_bib()
		for i in range(8):
			self.state[i + 8] = Uint32(self.ivs[i])
		self.state = self.digest_context(context)

	def compute_bib(self) -> Uint64:
		bi1 = (self.state[0] ^ self.key[0]).to_bytes()
		bi2 = (self.state[1] ^ self.key[1]).to_bytes()
		return Uint64.from_bytes(bi1 + bi2, byteorder="little")

	def digest_context(self, context: bytes) -> list[Uint32]:
		ctx = utils.bytes_to_uint32_vector(context, size=32)
		clone = self.clone()
		clone.compress(ctx[:16], index=0)
		clone.compress(ctx[16:], index=1)
		return clone.state

	def compress(self, message: list[Uint32], index: int) -> None:
		self.set_params(KDFDomain.DIGEST_CTX, index)
		for _ in range(6):
			self.mix_into_state(message)
			message = self.permute(message)
		self.set_params(KDFDomain.LAST_ROUND)
		self.mix_into_state(message)

	def derive_keys(self, index: int) -> list[list[Uint32]]:
		self.set_params(KDFDomain.DERIVE_KEY, index + 2)
		keys = []
		for _ in range(10):
			self.mix_into_state(self.key)
			self.key = self.permute(self.key)
			keys.append(self.state[4:8])
		self.set_params(KDFDomain.LAST_ROUND)
		self.mix_into_state(self.key)
		keys.append(self.state[4:8])
		return keys

	def clone(self) -> BlakeKeyGen:
		return deepcopy(self)
