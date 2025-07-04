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

from abc import ABC, abstractmethod
from copy import deepcopy

from src.blake_keygen.base_blake_keygen import *

__all__ = ["WithDeriveKeys32", "WithDeriveKeys64"]


class WithDeriveKeys32(BaseBlake, ABC):
    @staticmethod
    @abstractmethod
    def add_round_key(
            keygen: BaseBlake, round_keys: RoundKeys
    ) -> None: ...

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

            for _ in range(key_count - 1):
                self.add_round_key(keygen, round_keys)
                keygen.knc = keygen.permute(keygen.knc)
            self.add_round_key(keygen, round_keys)  # last round

        return blocks_round_keys


class WithDeriveKeys64(BaseBlake, ABC):
    @staticmethod
    @abstractmethod
    def add_round_key(
            keygen: BaseBlake, b1_round_keys: RoundKeys, b2_round_keys: RoundKeys
    ) -> None: ...

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

            for _ in range(key_count - 1):
                self.add_round_key(keygen, b1_round_keys, b2_round_keys)
                keygen.knc = keygen.permute(keygen.knc)
            self.add_round_key(keygen, b1_round_keys, b2_round_keys)  # last round

        _, keys1, keys2 = group1
        _, keys3, keys4 = group2

        return [keys1, keys2, keys3, keys4]
