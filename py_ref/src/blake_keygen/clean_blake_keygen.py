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

from src.blake_keygen.base_blake_keygen import BaseBlake, KDFDomain, RoundKeys
from src.blake_keygen.with_derive_keys import (WithDeriveKeys32,
                                               WithDeriveKeys64)
from src.integers import BaseUint, Uint8, Uint32, Uint64

__all__ = ["Blake32", "Blake64"]


class Blake32(WithDeriveKeys32):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint32

    @staticmethod
    def create_uint(value: int) -> BaseUint:
        return Uint32(value)

    @staticmethod
    def bit_length() -> int:
        return Uint32.bit_length()

    @staticmethod
    def rots() -> tuple[int, ...]:
        return 16, 12, 8, 7

    @staticmethod
    def ivs() -> tuple[int, ...]:
        return (  # From BLAKE2s, which in turn took them from SHA-256
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        )  # fmt: skip

    @staticmethod
    def domain_mask(domain: KDFDomain) -> int:
        return {
            KDFDomain.CTX: 0,
            KDFDomain.MSG: 0x00F0000F,
            KDFDomain.HDR: 0x0F000F00,
            KDFDomain.CHK: 0xF00F0000,
        }[domain]

    @staticmethod
    def add_round_key(keygen: BaseBlake, round_keys: RoundKeys) -> None:
        keygen.mix_into_state(keygen.knc)
        block_rk = [Uint8(b) for v in keygen.state[4:8] for b in v.to_bytes()]
        round_keys.append(block_rk)


class Blake64(WithDeriveKeys64):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint64

    @staticmethod
    def create_uint(value: int) -> BaseUint:
        return Uint64(value)

    @staticmethod
    def bit_length() -> int:
        return Uint64.bit_length()

    @staticmethod
    def rots() -> tuple[int, ...]:
        return 32, 24, 16, 63

    @staticmethod
    def ivs() -> tuple[int, ...]:
        return (  # From BLAKE2b, which in turn took them from SHA-512
            0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
            0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
        )  # fmt: skip

    @staticmethod
    def domain_mask(domain: KDFDomain) -> int:
        return {
            KDFDomain.CTX: 0,
            KDFDomain.MSG: 0x0000FF00000000FF,
            KDFDomain.HDR: 0x00FF000000FF0000,
            KDFDomain.CHK: 0xFF0000FF00000000,
        }[domain]

    @staticmethod
    def add_round_key(keygen: BaseBlake, b1_round_keys: RoundKeys, b2_round_keys: RoundKeys) -> None:
        keygen.mix_into_state(keygen.knc)
        block1_rk = [Uint8(b) for v in keygen.state[4:6] for b in v.to_bytes()]
        block2_rk = [Uint8(b) for v in keygen.state[6:8] for b in v.to_bytes()]
        b1_round_keys.append(block1_rk)
        b2_round_keys.append(block2_rk)
