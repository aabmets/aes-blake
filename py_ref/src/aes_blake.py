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
        header_checksums = CheckSum.create_many(self.aes_blocks_count)
        final_checksum: list[Uint8] = []
        ciphertext: list[Uint8] = []

        # Encrypt the plaintext, store the ciphertext, and XOR the plaintext into plaintext checksum
        for group in utils.group_by(plaintext_chunks, self.aes_blocks_count):
            group_keys = self.keygen.derive_keys(self.key_count, self.block_counter, KDFDomain.MSG)
            aes_blocks: list[AESBlock] = []

            for chunk, keys, chk in zip(group, group_keys, plaintext_checksums):
                aes_blocks.append(AESBlock(chunk, keys))
                chk.xor_with(chunk)

            self.run_encryption_rounds(aes_blocks)
            for block in aes_blocks:
                ciphertext.extend(block.state)

            self.block_counter += 1

        # Encrypt the header and XOR the ciphertext into header checksum
        for group in utils.group_by(header_chunks, self.aes_blocks_count):
            group_keys = self.keygen.derive_keys(self.key_count, self.block_counter, KDFDomain.HDR)
            aes_blocks: list[AESBlock] = []

            for chunk, keys in zip(group, group_keys):
                aes_blocks.append(AESBlock(chunk, keys))

            self.run_encryption_rounds(aes_blocks)
            for chk, block in zip(header_checksums, aes_blocks):
                chk.xor_with(block.state)

            self.block_counter += 1

        # Encrypt the plaintext checksum and XOR it with the header checksum into final checksum
        group_keys = self.keygen.derive_keys(self.key_count, self.block_counter, KDFDomain.CHK)
        aes_blocks: list[AESBlock] = []

        for chk, keys in zip(plaintext_checksums, group_keys):
            aes_blocks.append(AESBlock(chk.state, keys))

        self.run_encryption_rounds(aes_blocks)

        for aes_block, chk in zip(aes_blocks, header_checksums):
            for uint1, uint2 in zip(aes_block.state, chk.state):
                final_checksum.append(uint1 ^ uint2)

        self.block_counter = 0
        return bytes(ciphertext), bytes(final_checksum)  # Return the ciphertext and the final checksum

    def decrypt(self, ciphertext: bytes, header: bytes, auth_tag: bytes) -> bytes:
        ciphertext_chunks, header_chunks = self.validate_convert_inputs(ciphertext, header)
        plaintext_checksums = CheckSum.create_many(self.aes_blocks_count)
        header_checksums = CheckSum.create_many(self.aes_blocks_count)
        final_checksum: list[Uint8] = []
        plaintext: list[Uint8] = []

        # Decrypt the ciphertext, store the plaintext, and XOR the retrieved plaintext into plaintext checksum
        for group in utils.group_by(ciphertext_chunks, self.aes_blocks_count):
            group_keys = self.keygen.derive_keys(self.key_count, self.block_counter, KDFDomain.MSG)
            aes_blocks: list[AESBlock] = []

            for chunk, keys in zip(group, group_keys):
                aes_blocks.append(AESBlock(chunk, keys))

            self.run_decryption_rounds(aes_blocks)
            for chk, block in zip(plaintext_checksums, aes_blocks):
                plaintext.extend(block.state)
                chk.xor_with(block.state)

            self.block_counter += 1

        # Encrypt the header and XOR the ciphertext into header checksum
        for group in utils.group_by(header_chunks, self.aes_blocks_count):
            group_keys = self.keygen.derive_keys(self.key_count, self.block_counter, KDFDomain.HDR)
            aes_blocks: list[AESBlock] = []

            for chunk, keys in zip(group, group_keys):
                aes_blocks.append(AESBlock(chunk, keys))

            self.run_encryption_rounds(aes_blocks)
            for chk, block in zip(header_checksums, aes_blocks):
                chk.xor_with(block.state)

            self.block_counter += 1

        # Encrypt the plaintext checksum and XOR it with the header checksum into final checksum
        group_keys = self.keygen.derive_keys(self.key_count, self.block_counter, KDFDomain.CHK)
        aes_blocks: list[AESBlock] = []

        for chk, keys in zip(plaintext_checksums, group_keys):
            aes_blocks.append(AESBlock(chk.state, keys))

        self.run_encryption_rounds(aes_blocks)

        for aes_block, chk in zip(aes_blocks, header_checksums):
            for uint1, uint2 in zip(aes_block.state, chk.state):
                final_checksum.append(uint1 ^ uint2)

        # If tags match, the correct plaintext has been decrypted
        assert bytes(final_checksum) == auth_tag

        self.block_counter = 0
        return bytes(plaintext)

    def validate_convert_inputs(self, text: bytes, header: bytes) -> Inputs:
        for data in [text, header]:
            assert (len(data) % self.aes_total_bytes) == 0
        a = utils.split_bytes(text, chunk_size=self.aes_block_bytes)
        b = utils.split_bytes(header, chunk_size=self.aes_block_bytes)
        return a, b

    def run_encryption_rounds(self, aes_blocks: list[AESBlock]) -> None:
        generators = [ab.encrypt() for ab in aes_blocks]
        keep_running = True
        while keep_running:
            for gen in generators:
                keep_running = next(gen, False)
            self.exchange_columns(aes_blocks)

    def run_decryption_rounds(self, aes_blocks: list[AESBlock]) -> None:
        generators = [ab.decrypt() for ab in aes_blocks]
        keep_running = True
        while keep_running:
            self.exchange_columns(aes_blocks, inverse=True)
            for gen in generators:
                keep_running = next(gen, False)

    def exchange_columns(self, aes_blocks: list[AESBlock], inverse=False) -> None:
        clones = [block.clone() for block in aes_blocks]
        pattern = self.ex_cols_pattern(inverse)
        for i, indices in enumerate(pattern):
            aes_blocks[i].state = [
                *clones[indices[0]].state[0:4],
                *clones[indices[1]].state[4:8],
                *clones[indices[2]].state[8:12],
                *clones[indices[3]].state[12:16],
            ]


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
