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
from enum import Enum
from abc import ABC, abstractmethod

from src.integers import *

__all__ = ["AnyUintList", "RoundKeys", "KDFDomain", "BaseBlake"]


AnyUintList = list[BaseUint] | list[BaseMaskedUint]
RoundKeys = list[list[Uint8]]


class KDFDomain(Enum):
    CTX = 0  # Digest context
    MSG = 1  # Derive message block keys
    HDR = 2  # Derive header block keys
    CHK = 3  # Derive checksum block keys


class BaseBlake(ABC):
    @staticmethod
    @abstractmethod
    def uint_class() -> t.Type[BaseUint] | t.Type[BaseMaskedUint]: ...

    @staticmethod
    @abstractmethod
    def create_uint(value: int) -> BaseUint | BaseMaskedUint: ...

    @staticmethod
    @abstractmethod
    def bit_length() -> int: ...

    @staticmethod
    @abstractmethod
    def rots() -> tuple[int, ...]: ...

    @staticmethod
    @abstractmethod
    def ivs() -> tuple[int, ...]: ...

    @staticmethod
    @abstractmethod
    def domain_mask(domain: KDFDomain) -> int: ...

    @abstractmethod
    def derive_keys(
            self, key_count: int, block_counter: int, domain: KDFDomain
    ) -> list[RoundKeys]: ...

    def __init__(self, key: bytes, nonce: bytes, context: bytes) -> None:
        self.key = self.bytes_to_uint_vector(key, vec_len=8)
        self.nonce = self.bytes_to_uint_vector(nonce, vec_len=8)
        self.context = self.bytes_to_uint_vector(context, vec_len=16)
        self.state = [self.create_uint(0) for _ in range(16)]
        self.knc = self.compute_key_nonce_composite()

    @classmethod
    def bytes_to_uint_vector(cls, data: bytes, vec_len: int) -> AnyUintList:
        chunk_size = cls.bit_length() // 8
        pad_size = chunk_size * vec_len
        sized_data = (data + b"\x00" * pad_size)[:pad_size]
        output: AnyUintList = []
        for i in range(0, len(sized_data), chunk_size):
            chunk = sized_data[i:i + chunk_size]
            value = int.from_bytes(chunk, byteorder="big", signed=False)
            output.append(cls.create_uint(value))
        return output

    def compute_key_nonce_composite(self) -> list[BaseUint]:
        """
        Splices together 8-element key and nonce vectors by exchanging the bits
        of a pair of elements from each vector according to predefined bit-masks.

        Returns:
            list[BaseUint]: 16-element vector of combined elements.
        """
        half = self.bit_length() // 2
        mask1 = (1 << half) - 1  # Selects half of the lower bits
        mask2 = mask1 << half  # Selects half of the upper bits
        out: list[BaseUint] = []
        for i in range(8):
            a = (self.key[i] & mask2) | (self.nonce[i] & mask1)
            b = (self.nonce[i] & mask2) | (self.key[i] & mask1)
            out.extend([a, b])
        return out

    def init_state_vector(self, entropy: list[BaseUint], counter: int, domain: KDFDomain) -> None:
        """
        Initialize the 16-word internal state vector for the compression function.

        State layout:
          Words 0–3: Initial IV constants.
          Words 4–11: Entropy words (8-element list):
            - Add the low 32 bits of the counter to words 4, 5, 6, and 7.
            - Add the high 32 bits of the counter to words 8, 9, 10, and 11.
          Words 12–15: Remaining IV constants:
            - XOR each word with the domain separation mask.

        Args:
            entropy (list[BaseUint]): An 8-element list of entropy words.
            counter (int): A 64-bit block counter.
            domain (KDFDomain): Domain separation value for the current state.

        Returns:
            None: The internal state is modified in-place.
        """
        ivs = self.ivs()
        self.state.clear()
        self.state.extend(self.create_uint(iv) for iv in ivs[:4])
        self.state.extend(entropy)
        self.state.extend(self.create_uint(iv) for iv in ivs[4:])
        mask = Uint32.max_value()
        ctr_low = Uint32(counter & mask)
        ctr_high = Uint32((counter >> 32) & mask)
        for i in range(4, 8):
            self.state[i] += ctr_low
            self.state[i + 4] += ctr_high
        d_mask = self.domain_mask(domain)
        for i in range(12, 16):
            self.state[i] ^= d_mask

    def mix_into_state(self, m: list[BaseUint]) -> None:
        """
        Performs the BLAKE3 mixing function on the
        internal state using the provided message words.

        This function applies two rounds of the G mixing function:
        first across the columns of the state matrix, then across the diagonals.
        Each call to `g_mix` uses a pair of message words from the input list.

        Args:
            m (list[BaseUint]): A list of 16 message words used for the mixing.

        Returns:
            None: The internal state vector is modified in-place.
        """
        # columnar mixing
        self.g_mix(0, 4, 8, 12, m[0], m[1])
        self.g_mix(1, 5, 9, 13, m[2], m[3])
        self.g_mix(2, 6, 10, 14, m[4], m[5])
        self.g_mix(3, 7, 11, 15, m[6], m[7])
        # diagonal mixing
        self.g_mix(0, 5, 10, 15, m[8], m[9])
        self.g_mix(1, 6, 11, 12, m[10], m[11])
        self.g_mix(2, 7, 8, 13, m[12], m[13])
        self.g_mix(3, 4, 9, 14, m[14], m[15])

    def g_mix(self, a: int, b: int, c: int, d: int, mx: BaseUint, my: BaseUint) -> None:
        """
        Performs the BLAKE3 G mixing function on four state vector elements.

        This function applies two rounds of mixing operations to elements at
        indices a, b, c, and d of the internal state vector using the provided
        message words mx and my. Each round consists of additions, XORs, and
        bit rotations by amounts defined in the subclass (Blake32 or Blake64).

        Args:
            a (int): Index of the first element in the state vector.
            b (int): Index of the second element in the state vector.
            c (int): Index of the third element in the state vector.
            d (int): Index of the fourth element in the state vector.
            mx (BaseUint): First message word used in mixing.
            my (BaseUint): Second message word used in mixing.

        Returns:
            None: The internal state vector is modified in-place.
        """
        vec, rots = self.state, self.rots()
        # first mixing
        vec[a] = vec[a] + vec[b] + mx
        vec[d] = (vec[d] ^ vec[a]).rotr(rots[0])
        vec[c] = vec[c] + vec[d]
        vec[b] = (vec[b] ^ vec[c]).rotr(rots[1])
        # second mixing
        vec[a] = vec[a] + vec[b] + my
        vec[d] = (vec[d] ^ vec[a]).rotr(rots[2])
        vec[c] = vec[c] + vec[d]
        vec[b] = (vec[b] ^ vec[c]).rotr(rots[3])

    @staticmethod
    def permute(m: list[BaseUint]) -> list[BaseUint]:
        """
        Performs the BLAKE3 message permutation on the input message vector.

        The function reorders a list of BaseUint elements according to the
        fixed BLAKE3 permutation schedule and returns the permuted list.

        Args:
            m (list[BaseUint]): The input message vector to permute.

        Returns:
            list[BaseUint]: The permuted message vector.
        """
        schedule = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
        return [m[i] for i in schedule]

    def digest_context(self) -> None:
        """
        Digest the internal context through ten rounds of compression.

        This method initializes the internal state for the CTX domain using
        the stored key and a zero counter, then performs ten rounds of the
        BLAKE-like compression on the context vector:
          - For the first nine rounds:
            - Mix the context into the state.
            - Permute the context vector.
          - For the tenth round:
            - Mix the context into the state without further permutation.
          - Finally, apply the AES SubBytes transformation to the state.

        Returns:
            None: The internal state and context are updated in-place.
        """
        self.init_state_vector(self.key, counter=0, domain=KDFDomain.CTX)
        for _ in range(9):
            self.mix_into_state(self.context)
            self.context = self.permute(self.context)
        self.mix_into_state(self.context)  # 10th round
