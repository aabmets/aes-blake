#
#   Apache License 2.0
#
#   Copyright (c) 2024, Mattias Aabmets
#
#   The contents of this file are subject to the terms and conditions defined in the License.
#   You may not use, modify, or distribute this file except in compliance with the License.
#
#   SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

import typing as t
from abc import ABC, abstractmethod

from src import utils
from src.uint import Uint8
from src.aes_block import AESBlock
from src.blake_keygen import KDFDomain, Blake32, Blake64
from src.checksum import CheckSum

__all__ = ["BaseAESBlake", "AESBlake256", "AESBlake512"]

Inputs = tuple[list[bytes], list[bytes]]
Chunks = t.Iterable[bytes | Uint8]


class BaseAESBlake(ABC):
    @staticmethod
    @abstractmethod
    def keygen_class() -> t.Type[Blake32 | Blake64]: ...

    @staticmethod
    @abstractmethod
    def ex_cols_pattern(inverse: bool = False) -> tuple[list[int], ...]: ...

    def __init__(self, key: bytes, nonce: bytes, context: bytes) -> None:
        self.keygen: Blake32 | Blake64 = self.keygen_class()(key, nonce, context)
        self.keygen.digest_context()
        self.aes_block_bytes = 16
        self.aes_blocks_count = self.keygen.uint().bit_count() // 16
        self.aes_total_bytes = self.aes_blocks_count * self.aes_block_bytes
        self.block_counter = 0
        self.key_count = 11

    def encrypt(self, plaintext: bytes, header: bytes) -> tuple[bytes, bytes]:
        plaintext_chunks, header_chunks = self.validate_convert_inputs(plaintext, header)
        plaintext_checksums = CheckSum.create_many(self.aes_blocks_count)
        ciphertext: list[Uint8] = []
        for chunk_group in utils.group_by(plaintext_chunks, self.aes_blocks_count):
            aes_blocks = self.run_encryption_rounds(chunk_group, KDFDomain.MSG)
            for block in aes_blocks:
                ciphertext.extend(block.state)
            for chk, chunk in zip(plaintext_checksums, chunk_group):
                chk.xor_with(chunk)
            self.block_counter += 1
        auth_tag = self.compute_auth_tag(header_chunks, plaintext_checksums)
        return bytes(ciphertext), auth_tag

    def decrypt(self, ciphertext: bytes, header: bytes, auth_tag: bytes) -> bytes:
        ciphertext_chunks, header_chunks = self.validate_convert_inputs(ciphertext, header)
        plaintext_checksums = CheckSum.create_many(self.aes_blocks_count)
        plaintext: list[Uint8] = []
        for chunk_group in utils.group_by(ciphertext_chunks, self.aes_blocks_count):
            aes_blocks = self.run_decryption_rounds(chunk_group, KDFDomain.MSG)
            for chk, block in zip(plaintext_checksums, aes_blocks):
                plaintext.extend(block.state)
                chk.xor_with(block.state)
            self.block_counter += 1
        new_auth_tag = self.compute_auth_tag(header_chunks, plaintext_checksums)
        if new_auth_tag != auth_tag:
            raise ValueError("Failed to verify auth tag")
        return bytes(plaintext)

    def validate_convert_inputs(self, text: bytes, header: bytes) -> Inputs:
        for data in [text, header]:
            if (len(data) % self.aes_total_bytes) != 0:
                raise ValueError("Invalid input data length")
        a = utils.split_bytes(text, chunk_size=self.aes_block_bytes)
        b = utils.split_bytes(header, chunk_size=self.aes_block_bytes)
        return a, b

    def run_encryption_rounds(self, chunks: Chunks, domain: KDFDomain) -> list[AESBlock]:
        aes_blocks = self.create_aes_blocks(chunks, domain)
        generators = [ab.encrypt() for ab in aes_blocks]
        keep_running = True
        while keep_running:
            for gen in generators:
                keep_running = next(gen, False)
            self.exchange_columns(aes_blocks)
        return aes_blocks

    def run_decryption_rounds(self, chunks: Chunks, domain: KDFDomain) -> list[AESBlock]:
        aes_blocks = self.create_aes_blocks(chunks, domain)
        generators = [ab.decrypt() for ab in aes_blocks]
        keep_running = True
        while keep_running:
            self.exchange_columns(aes_blocks, inverse=True)
            for gen in generators:
                keep_running = next(gen, False)
        return aes_blocks

    def create_aes_blocks(self, chunks: Chunks, domain: KDFDomain) -> list[AESBlock]:
        keys = self.keygen.derive_keys(self.key_count, self.block_counter, domain)
        return [AESBlock(chunk, k) for chunk, k in zip(chunks, keys)]

    def exchange_columns(self, aes_blocks: list[AESBlock], inverse: bool = False) -> None:
        clones = [block.clone() for block in aes_blocks]
        pattern = self.ex_cols_pattern(inverse)
        for i, indices in enumerate(pattern):
            aes_blocks[i].state = [
                *clones[indices[0]].state[0:4],
                *clones[indices[1]].state[4:8],
                *clones[indices[2]].state[8:12],
                *clones[indices[3]].state[12:16],
            ]

    def compute_auth_tag(self, header_chunks: list[bytes], plaintext_checksums: list[CheckSum]) -> bytes:
        header_checksums = CheckSum.create_many(self.aes_blocks_count)
        for chunk_group in utils.group_by(header_chunks, self.aes_blocks_count):
            aes_blocks = self.run_encryption_rounds(chunk_group, KDFDomain.HDR)
            for chk, block in zip(header_checksums, aes_blocks):
                chk.xor_with(block.state)
            self.block_counter += 1
        chk_states = [chk.state for chk in plaintext_checksums]
        aes_blocks = self.run_encryption_rounds(chk_states, KDFDomain.CHK)
        final_checksum: list[Uint8] = []
        for aes_block, chk in zip(aes_blocks, header_checksums):
            for uint1, uint2 in zip(aes_block.state, chk.state):
                final_checksum.append(uint1 ^ uint2)
        self.block_counter = 0
        return bytes(final_checksum)


class AESBlake256(BaseAESBlake):
    @staticmethod
    def keygen_class() -> t.Type[Blake32]:
        return Blake32

    @staticmethod
    def ex_cols_pattern(inverse: bool = False) -> tuple[list[int], ...]:
        enc = [0, 1, 0, 1], [1, 0, 1, 0]
        dec = [0, 1, 0, 1], [1, 0, 1, 0]
        return dec if inverse else enc


class AESBlake512(BaseAESBlake):
    @staticmethod
    def keygen_class() -> t.Type[Blake64]:
        return Blake64

    @staticmethod
    def ex_cols_pattern(inverse: bool = False) -> tuple[list[int], ...]:
        enc = [0, 1, 2, 3], [1, 2, 3, 0], [2, 3, 0, 1], [3, 0, 1, 2]
        dec = [0, 3, 2, 1], [1, 0, 3, 2], [2, 1, 0, 3], [3, 2, 1, 0]
        return dec if inverse else enc
