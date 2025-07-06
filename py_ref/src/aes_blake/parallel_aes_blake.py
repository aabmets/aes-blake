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

import os
import typing as t
from abc import ABC
from concurrent.futures import ProcessPoolExecutor

import dill as pickle

from src.aes_blake import BaseAESBlake
from src.blake_keygen import KDFDomain
from src.checksum import BaseCheckSum

__all__ = ["ParallelAESBlakeMixin"]


Group = t.Tuple[bytes, ...]
WorkerReturn = t.Tuple[int, bytes, list[BaseCheckSum]]
Worker = t.Callable[[bytes, int, Group], WorkerReturn]


def _enc_worker(blob: bytes, index: int, group: Group) -> WorkerReturn:
    cipher: BaseAESBlake = pickle.loads(blob)
    cipher.block_counter += index

    aes_blocks = cipher.run_encryption_rounds(group, KDFDomain.MSG)
    ciphertext = b"".join(bytes(b.state) for b in aes_blocks)

    chk_cls = cipher.checksum_class()
    checksums = chk_cls.create_many(cipher.aes_blocks_count)
    for chk, chunk in zip(checksums, group, strict=True):
        chk.xor_with(chunk)

    return index, ciphertext, checksums


def _dec_worker(blob: bytes, index: int, group: Group) -> WorkerReturn:
    cipher: BaseAESBlake = pickle.loads(blob)
    cipher.block_counter += index

    aes_blocks = cipher.run_decryption_rounds(group, KDFDomain.MSG)
    plaintext = b"".join(bytes(b.state) for b in aes_blocks)

    chk_cls = cipher.checksum_class()
    checksums = chk_cls.create_many(cipher.aes_blocks_count)
    for chk, block in zip(checksums, aes_blocks, strict=True):
        chk.xor_with(block.state)

    return index, plaintext, checksums


def _hdr_worker(blob: bytes, index: int, group: Group) -> WorkerReturn:
    cipher: BaseAESBlake = pickle.loads(blob)
    cipher.block_counter += index

    aes_blocks = cipher.run_encryption_rounds(group, KDFDomain.HDR)

    chk_cls = cipher.checksum_class()
    checksums = chk_cls.create_many(cipher.aes_blocks_count)
    for chk, block in zip(checksums, aes_blocks, strict=True):
        chk.xor_with(block.state)

    return index, b"", checksums


class ParallelAESBlakeMixin(BaseAESBlake, ABC):
    _cpu_count = max(1, os.cpu_count() or 1)

    def _run_pool(
            self,
            chunks: list[bytes],
            worker: t.Callable,
            header_chunks: list[bytes] = None
    ) -> t.Tuple[bytes, bytes]:
        chk_cls = self.checksum_class()
        text_checksums = chk_cls.create_many(self.aes_blocks_count)
        chunk_groups = list(self.group_by(chunks, self.aes_blocks_count))
        bytes_out  = [b""] * len(chunk_groups)
        blob = pickle.dumps(self)

        with ProcessPoolExecutor(max_workers=self._cpu_count) as pool:
            futures = [
                pool.submit(worker, blob, index, group)
                for index, group in enumerate(chunk_groups)
            ]
            for fut in futures:
                index, text, checksums = fut.result()
                bytes_out[index] = text
                for parent, child in zip(text_checksums, checksums, strict=True):
                    parent.xor_with(child.state)

        self.block_counter += len(chunk_groups)
        auth_tag = self.compute_auth_tag(header_chunks, text_checksums)
        return b"".join(bytes_out), auth_tag

    def encrypt(self, plaintext: bytes, header: bytes) -> t.Tuple[bytes, bytes]:
        p_chunks, h_chunks = self.validate_convert_inputs(plaintext, header)
        return self._run_pool(p_chunks, _enc_worker, h_chunks)

    def decrypt(self, ciphertext: bytes, header: bytes, auth_tag: bytes) -> bytes:
        c_chunks, h_chunks = self.validate_convert_inputs(ciphertext, header)
        plaintext, new_tag = self._run_pool(c_chunks, _dec_worker, h_chunks)
        if new_tag != auth_tag:
            raise ValueError("Failed to verify auth tag")
        return plaintext

    def compute_auth_tag(
        self,
        header_chunks: list[bytes],
        plaintext_checksums,
    ) -> bytes:
        chk_cls = self.checksum_class()
        header_checksums = chk_cls.create_many(self.aes_blocks_count)
        header_groups = list(self.group_by(header_chunks, self.aes_blocks_count))
        blob = pickle.dumps(self)

        with ProcessPoolExecutor(max_workers=self._cpu_count) as pool:
            futures = [pool.submit(_hdr_worker, blob, i, grp)
                    for i, grp in enumerate(header_groups)]
            for fut in futures:
                _, _, chk_lst = fut.result()
                for parent, child in zip(header_checksums, chk_lst, strict=True):
                    parent.xor_with(child.state)

        self.block_counter += len(header_groups)
        chk_states = [chk.state for chk in plaintext_checksums]
        aes_blocks = self.run_encryption_rounds(chk_states, KDFDomain.CHK)

        final_checksum = []
        for aes_block, chk in zip(aes_blocks, header_checksums, strict=True):
            for u1, u2 in zip(aes_block.state, chk.state, strict=True):
                final_checksum.append(u1 ^ u2)

        self.block_counter = 0
        return bytes(final_checksum)
