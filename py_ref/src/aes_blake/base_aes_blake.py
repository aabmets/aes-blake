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

from src.integers import *
from src.aes_block import *
from src.blake_keygen import *
from src.checksum import *

__all__ = ["BaseAESBlake"]


Inputs = tuple[list[bytes], list[bytes]]
Chunks = t.Iterable[bytes | Uint8]


class BaseAESBlake(ABC):
    @staticmethod
    @abstractmethod
    def keygen_class() -> t.Type[Blake32 | Blake64]: ...

    @staticmethod
    @abstractmethod
    def aes_class() -> t.Type[AESBlock]: ...

    @staticmethod
    @abstractmethod
    def checksum_class() -> t.Type[CheckSum]: ...

    @staticmethod
    @abstractmethod
    def ex_cols_pattern(inverse: bool = False) -> tuple[list[int], ...]: ...

    def __init__(self, key: bytes, nonce: bytes, context: bytes) -> None:
        self.keygen: Blake32 | Blake64 = self.keygen_class()(key, nonce, context)
        self.keygen.digest_context()
        self.aes_block_bytes = 16
        self.aes_blocks_count = self.keygen.bit_length() // 16
        self.aes_total_bytes = self.aes_blocks_count * self.aes_block_bytes
        self.block_counter = 0
        self.key_count = 11

    def encrypt(self, plaintext: bytes, header: bytes) -> tuple[bytes, bytes]:
        plaintext_chunks, header_chunks = self.validate_convert_inputs(plaintext, header)
        plaintext_checksums = self.checksum_class().create_many(self.aes_blocks_count)
        ciphertext: list[Uint8] = []
        for chunk_group in self.group_by(plaintext_chunks, self.aes_blocks_count):
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
        plaintext_checksums = self.checksum_class().create_many(self.aes_blocks_count)
        plaintext: list[Uint8] = []
        for chunk_group in self.group_by(ciphertext_chunks, self.aes_blocks_count):
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
        a = self.split_bytes(text, chunk_size=self.aes_block_bytes)
        b = self.split_bytes(header, chunk_size=self.aes_block_bytes)
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
        return [self.aes_class()(chunk, k) for chunk, k in zip(chunks, keys)]

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

    def compute_auth_tag(self, header_chunks: list[bytes], plaintext_checksums: list[BaseCheckSum]) -> bytes:
        header_checksums = self.checksum_class().create_many(self.aes_blocks_count)
        for chunk_group in self.group_by(header_chunks, self.aes_blocks_count):
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

    @staticmethod
    def split_bytes(data: bytes, chunk_size: int) -> list[bytes]:
        return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    @staticmethod
    def group_by(data: list, size: int) -> list[tuple]:
        n = len(data)
        if not data:
            raise ValueError("Data cannot be an empty list")
        elif size <= 0:
            raise ValueError("Size must be a positive integer")
        elif n % size != 0:
            raise ValueError(f"Cannot divide list of length {n} into groups of {size}")
        return [tuple(data[i:i+size]) for i in range(0, n, size)]
