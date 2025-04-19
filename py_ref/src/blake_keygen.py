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

from collections.abc import Generator
from copy import deepcopy
from enum import Enum

from src import utils
from src.aes_sbox import SBox
from src.uint import Uint32, Uint64, Uint8

__all__ = ["KDFDomain", "BlakeKeyGen"]


class KDFDomain(Enum):
    DIGEST_CTX = 0x10  # 0001 0000
    CIPHER_OPS = 0x20  # 0010 0000
    HEADER_CHK = 0x40  # 0100 0000
    LAST_ROUND = 0x80  # 1000 0000


class BlakeKeyGen:
    compression_rounds = 10
    state: list[Uint32]

    ivs = (  # From BLAKE3, which in turn took them from SHA-256
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,  # 08, 09, 10, 11
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,  # 12, 13, 14, 15
    )  # fmt: skip

    def __init__(self, key: bytes, nonce: bytes) -> None:
        self.validate_params(key, nonce)
        self.key = utils.bytes_to_uint32_vector(key, size=16)
        self.state = utils.bytes_to_uint32_vector(nonce, size=16)
        self.bcb = self.compute_block_counter_base(key, nonce)
        for i in range(8):
            self.state[i + 8] = Uint32(self.ivs[i])

    @staticmethod
    def validate_params(key: bytes, nonce: bytes) -> None:
        if not (32 <= len(key) <= 64):
            raise ValueError("Key size must be between 32 and 64 bytes")
        elif not (16 <= len(nonce) <= 32):
            raise ValueError("Nonce size must be between 16 and 32 bytes")

    @staticmethod
    def compute_block_counter_base(key: bytes, nonce: bytes) -> Uint64:
        nonce = utils.pad_trunc_to_size(nonce, size=8)
        key = utils.pad_trunc_to_size(key, size=8)
        key = [SBox.ENC.value[kb] for kb in key]
        bcb = [x ^ y for x, y in zip(key, nonce, strict=True)]
        return Uint64.from_bytes(bcb, byteorder="little")

    def digest_context(self, context: bytes) -> None:
        ctx = utils.bytes_to_uint32_vector(context, size=32)
        pair_1 = (ctx[:16], 0x00FF_0000_00FF_0000)
        pair_2 = (ctx[16:], 0xFF00_0000_FF00_0000)
        for message, counter in [pair_1, pair_2]:
            for _ in self.compress(message, counter, domain=KDFDomain.DIGEST_CTX):
                pass

    def compress(
        self,
        message: list[Uint32],
        counter: int,
        domain: KDFDomain
    ) -> Generator[list[Uint32], None, None]:
        self.set_params(domain, counter)
        for _ in range(self.compression_rounds):
            self.mix_into_state(message)
            message = self.permute(message)
            yield self.state[4:8]
        self.set_params(KDFDomain.LAST_ROUND)
        self.mix_into_state(message)
        yield self.state[4:8]

    def set_params(self, domain: KDFDomain = None, counter: int = None) -> None:
        if domain:
            for i in range(8, 12):
                self.state[i] ^= domain.value
        if counter:
            bcb_incr = (self.bcb + counter).to_bytes()
            ctr_low = Uint32.from_bytes(bcb_incr[4:], byteorder="little")
            ctr_high = Uint32.from_bytes(bcb_incr[:4], byteorder="little")
            for i in range(4):
                self.state[i] ^= ctr_low + i
                self.state[i + 12] ^= ctr_high

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

    @staticmethod
    def permute(m: list[Uint32]) -> list[Uint32]:
        pattern = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
        return [m[i] for i in pattern]

    def compute_round_keys(self, counter: int, domain: KDFDomain) -> list[list[Uint8]]:
        _self = deepcopy(self)  # clone
        keys: list[list[Uint8]] = []
        for chunk in _self.compress(_self.key, counter, domain):
            key: list[Uint8] = []
            for uint32 in chunk:
                for byte in uint32.to_bytes():
                    key.append(Uint8(byte))
            keys.append(key)
        return keys
