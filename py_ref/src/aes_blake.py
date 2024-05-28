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
import collections.abc as c
from enum import Enum
from .blake_keygen import BlakeKeyGen
from .aes_block import AESBlock
from .checksum import CheckSum
from . import utils


__all__ = ["Operation", "BlockSize", "AESBlake"]


class Operation(Enum):
	ENC = "encryption"
	DEC = "decryption"


class BlockSize(Enum):
	BITS_128 = 1
	BITS_256 = 2
	BITS_384 = 3
	BITS_512 = 4


class AESBlake:
	def __init__(self, key: bytes, context: bytes, block_size: BlockSize) -> None:
		self.key = key
		self.context = context
		self.block_size = block_size

	def encrypt(self, plaintext: bytes, nonce: bytes, header: bytes = b'') -> tuple[bytes, bytes]:
		bsv = self.block_size.value
		plaintext = utils.pkcs7_pad(plaintext, size=bsv * 16)
		keygen = BlakeKeyGen(self.key, nonce, self.context)
		checksums = [CheckSum() for _ in range(bsv)]
		ciphertext, counter = [], 0

		for i in range(0, len(plaintext), bsv * 16):
			chunks, blocks, gens = self.init_components(keygen, plaintext, i, counter, Operation.ENC)
			self.run_encryption_rounds(blocks, gens)
			for chunk, block, checksum in zip(chunks, blocks, checksums):
				ciphertext.extend(block.state)
				checksum.xor_with(chunk)
			counter += bsv

		tag = self.compute_auth_tag(keygen, checksums, header, counter)
		return bytes(ciphertext), tag

	def decrypt(self, ciphertext: bytes, tag: bytes, nonce: bytes, header: bytes = b'') -> bytes:
		bsv = self.block_size.value
		keygen = BlakeKeyGen(self.key, nonce, self.context)
		checksums = [CheckSum() for _ in range(bsv)]
		plaintext, counter = [], 0

		for i in range(0, len(ciphertext), bsv * 16):
			chunks, blocks, gens = self.init_components(keygen, ciphertext, i, counter, Operation.DEC)
			self.run_decryption_rounds(blocks, gens)

			for chunk, block, checksum in zip(chunks, blocks, checksums):
				plaintext.extend(bytes(block.state))
				checksum.xor_with(block.state)
			counter += bsv

		verif_tag = self.compute_auth_tag(keygen, checksums, header, counter)
		if verif_tag != tag:
			raise ValueError("Failed to verify auth tag!")
		return utils.pkcs7_unpad(bytes(plaintext))

	def compute_auth_tag(
			self,
			keygen: BlakeKeyGen,
			checksums: list[CheckSum],
			header: bytes,
			counter: int
	) -> bytes:
		plaintext_checksum = b''.join(chk.to_bytes() for chk in checksums)
		header_checksum = self.compute_header_checksum(keygen, header, counter)
		out = []
		for b1, b2 in zip(plaintext_checksum, header_checksum):  # type: int, int
			out.append(b1 ^ b2)
		return bytes(out)

	def compute_header_checksum(
			self,
			keygen: BlakeKeyGen,
			header: bytes,
			counter: int
	) -> bytes:
		bsv = self.block_size.value
		header = utils.pkcs7_pad(header, size=bsv * 16)
		checksums = [CheckSum() for _ in range(bsv)]

		for i in range(0, len(header), bsv * 16):
			chunks, blocks, gens = self.init_components(keygen, header, i, counter, Operation.ENC)
			self.run_encryption_rounds(blocks, gens)

			for chunk, block, checksum in zip(chunks, blocks, checksums):
				checksum.xor_with(block.state)
			counter += bsv

		return b''.join(chk.to_bytes() for chk in checksums)

	def init_components(
			self,
			keygen: BlakeKeyGen,
			text: bytes,
			pointer: int,
			counter: int,
			operation: Operation
	) -> tuple[list[bytes], list[AESBlock], list[c.Generator]]:
		chunks, blocks, gens = [], [], []
		for j in range(self.block_size.value):
			chunk: bytes = text[pointer:pointer + 16]
			chunks.append(chunk)
			block = AESBlock(keygen, chunk, counter + j)
			blocks.append(block)
			attr = f"{operation.value}_generator"
			generator = getattr(block, attr)
			gens.append(generator())
			pointer += 16
		return chunks, blocks, gens

	def run_encryption_rounds(self, blocks: list[AESBlock], gens: list[c.Generator]) -> None:
		stop = False
		while not stop:
			self.exchange_columns(blocks)
			for gen in gens:
				stop = next(gen, True)

	def run_decryption_rounds(self, blocks: list[AESBlock], gens: list[c.Generator]) -> None:
		stop = False
		while not stop:
			for gen in gens:
				stop = next(gen, True)
			self.exchange_columns(blocks, inverse=True)

	def exchange_columns(self, blocks: list[AESBlock], inverse=False) -> None:
		enc, dec = [], []
		if self.block_size == BlockSize.BITS_128:
			return
		elif self.block_size == BlockSize.BITS_256:
			enc = [0, 1, 0, 1], [1, 0, 1, 0]
			dec = [0, 1, 0, 1], [1, 0, 1, 0]
		elif self.block_size == BlockSize.BITS_384:
			enc = [0, 1, 2, 0], [1, 2, 0, 1], [2, 0, 1, 2]
			dec = [0, 2, 1, 0], [1, 0, 2, 1], [2, 1, 0, 2]
		elif self.block_size == BlockSize.BITS_512:
			enc = [0, 1, 2, 3], [1, 2, 3, 0], [2, 3, 0, 1], [3, 0, 1, 2]
			dec = [0, 3, 2, 1], [1, 0, 3, 2], [2, 1, 0, 3], [3, 2, 1, 0]
		blocks_order = dec if inverse else enc
		clones = [block.clone() for block in blocks]
		for i, indices in enumerate(blocks_order):
			blocks[i].state = [
				*clones[indices[0]].state[0:4],
				*clones[indices[1]].state[4:8],
				*clones[indices[2]].state[8:12],
				*clones[indices[3]].state[12:16]
			]
