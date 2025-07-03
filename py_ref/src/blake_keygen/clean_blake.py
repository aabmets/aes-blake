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
from copy import deepcopy

from src.blake_keygen.base_blake import *
from src.integers import *

__all__ = ["Blake32", "Blake64"]


class Blake32(BaseBlake):
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

    def derive_keys(
            self, key_count: int, block_counter: int, domain: KDFDomain
    ) -> list[RoundKeys]:
        """
        Derive a sequence of round keys for two 128-bit AES blocks
        using the 32-bit BLAKE variant.

        This method splits the internal state into two entropy sources and, for each:
          1. Creates a fresh Blake32 instance and initializes its state with the entropy,
             the provided block counter, and the specified domain.
          2. Iteratively mixes the key+nonce composite into the state and extracts
             a 128-bit round key (four state words, each yielding 4 bytes) for
             each of the key_count rounds. Between rounds, the key+nonce composite
             is permuted to ensure unique round keys.

        Args:
            key_count (int): Number of round keys to derive per 128-bit block.
            block_counter (int): 64-bit counter to introduce block-specific variance.
            domain (KDFDomain): Domain separation constant for key derivation.

        Returns:
            list[RoundKeys]: A two-element list, each containing `key_count` round keys.
                Each round key is a tuple of 16 Uint8 values (128 bits).
        """
        ent_src = deepcopy(self)
        entropy_1 = ent_src.state[0:4] + ent_src.state[8:12]
        entropy_2 = ent_src.state[4:8] + ent_src.state[12:16]
        blocks_round_keys: list[RoundKeys] = [[], []]

        for i, entropy in enumerate([entropy_1, entropy_2]):
            keygen = deepcopy(self)
            keygen.init_state_vector(entropy, block_counter, domain)
            round_keys = blocks_round_keys[i]

            def add_round_key():
                keygen.mix_into_state(keygen.knc)
                block_rk = [Uint8(b) for v in keygen.state[4:8] for b in v.to_bytes()]
                round_keys.append(block_rk)

            for _ in range(key_count - 1):
                add_round_key()
                keygen.knc = keygen.permute(keygen.knc)
            add_round_key()  # last round

        return blocks_round_keys


class Blake64(BaseBlake):
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

    def derive_keys(
            self, key_count: int, block_counter: int, domain: KDFDomain
    ) -> list[RoundKeys]:
        """
        Derive a sequence of round keys for four 128-bit AES blocks
        using the 64-bit BLAKE variant.

        This method splits the internal state into two entropy sources and, for each source:
          1. Creates a fresh Blake64 instance and initializes its state with the entropy,
             the provided block counter, and the specified domain.
          2. Iteratively mixes the key+nonce composite into the state and extracts
             two 128-bit round keys per round: one from state words 4–5 and another from 6–7.
          3. Between rounds, the key+nonce composite is permuted to ensure distinct keys.

        Args:
            key_count (int): Number of round keys to derive per block stream.
            block_counter (int): 64-bit counter to introduce block-specific variance.
            domain (KDFDomain): Domain separation constant for key derivation.

        Returns:
            list[RoundKeys]: A four-element list of round-keys lists [keys1, keys2, keys3, keys4].
                Each inner list contains `key_count` round keys, where each round key is a tuple
                of 16 Uint8 values (128 bits).
        """
        ent_src = deepcopy(self)
        entropy_1 = ent_src.state[0:4] + ent_src.state[8:12]
        entropy_2 = ent_src.state[4:8] + ent_src.state[12:16]
        group1 = (entropy_1, [], [])
        group2 = (entropy_2, [], [])

        for entropy, b1_round_keys, b2_round_keys in [group1, group2]:
            keygen = deepcopy(self)
            keygen.init_state_vector(entropy, block_counter, domain)

            def add_round_key():
                keygen.mix_into_state(keygen.knc)
                block1_rk = [Uint8(b) for v in keygen.state[4:6] for b in v.to_bytes()]
                block2_rk = [Uint8(b) for v in keygen.state[6:8] for b in v.to_bytes()]
                b1_round_keys.append(block1_rk)
                b2_round_keys.append(block2_rk)

            for _ in range(key_count - 1):
                add_round_key()
                keygen.knc = keygen.permute(keygen.knc)
            add_round_key()  # last round

        _, keys1, keys2 = group1
        _, keys3, keys4 = group2

        return [keys1, keys2, keys3, keys4]
