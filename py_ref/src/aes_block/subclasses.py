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

from src.aes_block.base_aes_block import BaseAESBlock
from src.aes_block.sbox import SBox
from src.integers import *

__all__ = ["AESBlock", "MaskedAESBlock"]


class AESBlock(BaseAESBlock):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint8

    @property
    def output(self) -> bytes:
        return bytes(self.state)

    def sub_bytes(self) -> None:
        for uint8 in self.state:
            uint8.value = SBox.ENC.value[uint8.value]

    def inv_sub_bytes(self) -> None:
        for uint8 in self.state:
            uint8.value = SBox.DEC.value[uint8.value]


class MaskedAESBlock(BaseAESBlock):
    @staticmethod
    def uint_class() -> t.Type[BaseMaskedUint]:
        return MaskedUint8

    @property
    def output(self) -> bytes:
        state = t.cast(list[MaskedUint8], self.state)
        unmasked_state = [s.unmask() for s in state]
        return bytes(unmasked_state)

    @staticmethod
    def _lsb_splat(bit: MaskedUint8) -> MaskedUint8:
        """Boolean-only expansion of the LSB (0→0x00, 1→0xFF)."""
        m = deepcopy(bit)
        m ^= m << 1
        m ^= m << 2
        m ^= m << 4
        return m

    def _gf_mul(self, x: MaskedUint8, y: MaskedUint8) -> MaskedUint8:
        """Constant-time multiply in GF(2^8)."""
        uint = self.uint_class()
        res = uint(0)
        for _ in range(8):
            lsb_mask = self._lsb_splat(y & uint(1))
            res ^= x & lsb_mask
            y >>= 1
            x = self.xtime(x)
        return res

    def _gf_inv(self, a: MaskedUint8) -> MaskedUint8:
        """Invert a byte in GF(2^8) by exponentiating to a²⁵⁴."""
        a2   = self._gf_mul(a, a)       # a²
        a4   = self._gf_mul(a2, a2)     # a⁴
        a8   = self._gf_mul(a4, a4)     # a⁸
        a16  = self._gf_mul(a8, a8)     # a¹⁶
        a32  = self._gf_mul(a16, a16)   # a³²
        a64  = self._gf_mul(a32, a32)   # a⁶⁴
        a128 = self._gf_mul(a64, a64)   # a¹²⁸
        tmp  = self._gf_mul(a128, a64)  # a¹⁹²
        tmp  = self._gf_mul(tmp, a32)   # a²²⁴
        tmp  = self._gf_mul(tmp, a16)   # a²⁴⁰
        tmp  = self._gf_mul(tmp, a8)    # a²⁴⁸
        tmp  = self._gf_mul(tmp, a4)    # a²⁵²
        inv  = self._gf_mul(tmp, a2)    # a²⁵⁴ ( = a⁻¹ in GF )
        return inv

    def _affine(self, x: MaskedUint8) -> MaskedUint8:
        """
        Apply the Rijndael affine map required for SubBytes:
        y = x ⊕ (x≪1) ⊕ (x≪2) ⊕ (x≪3) ⊕ (x≪4) ⊕ 0x63
        """
        uint = self.uint_class()
        return x ^ x.rotl(1) ^ x.rotl(2) ^ x.rotl(3) ^ x.rotl(4) ^ uint(0x63)

    def _inv_affine(self, y: MaskedUint8) -> MaskedUint8:
        """
        Apply the Rijndael inverse affine map required for InvSubBytes:
        x = (y≪1) ⊕ (y≪3) ⊕ (y≪6) ⊕ 0x05
        """
        uint = self.uint_class()
        return y.rotl(1) ^ y.rotl(3) ^ y.rotl(6) ^ uint(0x05)

    def sub_bytes(self) -> None:
        for i, byte in enumerate(self.state):
            self.state[i] = self._affine(self._gf_inv(byte))

    def inv_sub_bytes(self) -> None:
        for i, byte in enumerate(self.state):
            self.state[i] = self._gf_inv(self._inv_affine(byte))
