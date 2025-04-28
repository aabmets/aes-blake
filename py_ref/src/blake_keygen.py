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
from enum import Enum
from abc import ABC, abstractmethod

from src import utils
from src.aes_sbox import SBox
from src.uint import BaseUint, Uint8, Uint32, Uint64

__all__ = ["KDFDomain", "BaseBlake", "Blake32", "Blake64"]


RoundKey = tuple[
    Uint8, Uint8, Uint8, Uint8,
    Uint8, Uint8, Uint8, Uint8,
    Uint8, Uint8, Uint8, Uint8,
    Uint8, Uint8, Uint8, Uint8
]
RoundKeys = list[RoundKey]


class KDFDomain(Enum):
    DIGEST_CTX = 0
    CIPHER_BGN = 1
    CIPHER_MID = 2
    CIPHER_END = 3
    HEADER_BGN = 4
    HEADER_MID = 5
    HEADER_END = 6


class BaseBlake(ABC):
    @staticmethod
    @abstractmethod
    def uint() -> t.Type[BaseUint]: ...

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
    def derive_keys(self, counter: int, domain: KDFDomain) -> list[RoundKeys]: ...

    def __init__(self, key: bytes, nonce: bytes, context: bytes) -> None:
        self.key = utils.bytes_to_uint_vector(key, self.uint(), v_size=8)
        self.nonce = utils.bytes_to_uint_vector(nonce, self.uint(), v_size=8)
        self.context = utils.bytes_to_uint_vector(context, self.uint(), v_size=16)
        self.state = [self.uint()(0) for _ in range(16)]
        self.knc = self.compute_key_nonce_composite()

    def compute_key_nonce_composite(self) -> list[BaseUint]:
        """
        Splices together 8-element key and nonce vectors by exchanging the bits
        of a pair of elements from each vector according to predefined bit-masks.

        Returns:
            list[BaseUint]: 16 element vector of combined elements.
        """
        uint = self.uint()
        half = uint.bit_count() // 2
        mask1 = (1 << half) - 1  # Selects half of lower bits
        mask2 = mask1 << half  # Selects half of upper bits
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
            - Add the low 32 bits of the counter to words 4, 5, 6 and 7.
            - Add the high 32 bits of the counter to words 8, 9, 10 and 11.
          Words 12–15: Remaining IV constants:
            - XOR each word with the domain separation mask.

        Args:
            entropy (list[BaseUint]): An 8-element list of entropy words.
            counter (int): A 64-bit block counter.
            domain (KDFDomain): Domain separation value for the current state.

        Returns:
            None: The internal state is modified in-place.
        """
        cls, ivs = self.uint(), self.ivs()
        self.state.clear()
        self.state.extend(cls(iv) for iv in ivs[:4])
        self.state.extend(entropy)
        self.state.extend(cls(iv) for iv in ivs[4:])
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
        vec[d] = (vec[d] ^ vec[a]) >> rots[0]
        vec[c] = vec[c] + vec[d]
        vec[b] = (vec[b] ^ vec[c]) >> rots[1]
        # second mixing
        vec[a] = vec[a] + vec[b] + my
        vec[d] = (vec[d] ^ vec[a]) >> rots[2]
        vec[c] = vec[c] + vec[d]
        vec[b] = (vec[b] ^ vec[c]) >> rots[3]

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

    def sub_bytes(self, sbox: SBox = SBox.ENC) -> None:
        """
        Applies the AES SubBytes transformation to each word in-place.

        For each Uint object in the state:
          - Split into bytes.
          - Substitute each byte through the AES S-box.
          - Reassemble into a new Uint from the substituted bytes.

        Args:
            sbox (SBox): The AES S-box to use for transformation. This is parametrized
                for debugging purposes, the cipher always uses the encryption S-box.

        Returns:
            None: The internal state vector is modified in-place.
        """
        uint = self.uint()
        for i, v in enumerate(self.state):
            s_bytes = [sbox.value[b] for b in v.to_bytes()]
            self.state[i] = uint.from_bytes(s_bytes)

    def digest_context(self) -> None:
        """
        Digest the internal context through ten rounds of compression.

        This method initializes the internal state for the DIGEST_CTX domain using
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
        self.init_state_vector(self.key, counter=0, domain=KDFDomain.DIGEST_CTX)
        for _ in range(9):
            self.mix_into_state(self.context)
            self.context = self.permute(self.context)
        self.mix_into_state(self.context)  # 10th round
        self.sub_bytes()


class Blake32(BaseBlake):
    @staticmethod
    def uint() -> t.Type[Uint32]:
        return Uint32

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
            KDFDomain.DIGEST_CTX: 0,
            KDFDomain.CIPHER_BGN: 0x0F00000F,
            KDFDomain.CIPHER_MID: 0x0F0000F0,
            KDFDomain.CIPHER_END: 0x0F000F00,
            KDFDomain.HEADER_BGN: 0xF000F000,
            KDFDomain.HEADER_MID: 0xF00F0000,
            KDFDomain.HEADER_END: 0xF0F00000,
        }[domain]

    def derive_keys(self, counter: int, domain: KDFDomain) -> list[RoundKeys]:
        ent_src = deepcopy(self)
        entropy_1 = ent_src.state[0:4] + ent_src.state[8:12]
        entropy_2 = ent_src.state[4:8] + ent_src.state[12:16]
        blocks_round_keys: list[RoundKeys] = [[], []]

        for i, entropy in enumerate([entropy_1, entropy_2]):
            keygen = deepcopy(self)
            keygen.init_state_vector(entropy, counter, domain)
            round_keys = blocks_round_keys[i]

            def add_round_key():
                keygen.mix_into_state(keygen.knc)
                block_rk = [Uint8(b) for v in keygen.state[4:8] for b in v.to_bytes()]
                round_keys.append(t.cast(RoundKey, tuple(block_rk)))

            for _ in range(9):
                add_round_key()
                keygen.knc = keygen.permute(keygen.knc)
            add_round_key()  # 10th round

        return blocks_round_keys


class Blake64(BaseBlake):
    @staticmethod
    def uint() -> t.Type[Uint64]:
        return Uint64

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
            KDFDomain.DIGEST_CTX: 0,
            KDFDomain.CIPHER_BGN: 0x00FF0000000000FF,
            KDFDomain.CIPHER_MID: 0x00FF00000000FF00,
            KDFDomain.CIPHER_END: 0x00FF000000FF0000,
            KDFDomain.HEADER_BGN: 0xFF000000FF000000,
            KDFDomain.HEADER_MID: 0xFF0000FF00000000,
            KDFDomain.HEADER_END: 0xFF00FF0000000000,
        }[domain]

    def derive_keys(self, counter: int, domain: KDFDomain) -> list[RoundKeys]:
        ent_src = deepcopy(self)
        entropy_1 = ent_src.state[0:4] + ent_src.state[8:12]
        entropy_2 = ent_src.state[4:8] + ent_src.state[12:16]
        group1 = (entropy_1, [], [])
        group2 = (entropy_2, [], [])

        for entropy, b1_round_keys, b2_round_keys in [group1, group2]:
            keygen = deepcopy(self)
            keygen.init_state_vector(entropy, counter, domain)

            def add_round_key():
                keygen.mix_into_state(keygen.knc)
                block1_rk = [Uint8(b) for v in keygen.state[4:6] for b in v.to_bytes()]
                block2_rk = [Uint8(b) for v in keygen.state[6:8] for b in v.to_bytes()]
                b1_round_keys.append(t.cast(RoundKey, tuple(block1_rk)))
                b2_round_keys.append(t.cast(RoundKey, tuple(block2_rk)))

            for _ in range(9):
                add_round_key()
                keygen.knc = keygen.permute(keygen.knc)
            add_round_key()  # 10th round

        _, keys1, keys2 = group1
        _, keys3, keys4 = group2

        return [keys1, keys2, keys3, keys4]
