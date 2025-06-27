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

import secrets
import typing as t
import operator as opr
from abc import ABC
from enum import Enum
from src.uint import *

__all__ = ["Domain", "BaseMaskedUint", "MaskedUint8", "MaskedUint32", "MaskedUint64"]


class Domain(Enum):
    BOOLEAN = 0
    ARITHMETIC = 1


class BaseMaskedUint(ABC):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]: ...

    def __init__(self, value: int | BaseUint, order: int, domain: Domain) -> None:
        assert value >= 0, "Value must be greater than or equal to zero"
        assert order > 0, "Order must be greater than zero"
        assert domain in Domain, "Domain must be one of the defined domains"

        self.domain = domain
        self.order = order
        self.share_count = order + 1
        self.masking_fn = opr.xor if domain == Domain.BOOLEAN else opr.sub
        self.unmasking_fn = opr.xor if domain == Domain.BOOLEAN else opr.add
        self.masks = self.get_random_uints(order)
        self.masked_value: BaseUint = self.uint_class()(value)
        for mask in self.masks:
            self.masked_value = self.masking_fn(self.masked_value, mask)

    def get_random_uints(self, count: int):
        cls = self.uint_class()
        randbits = lambda: secrets.randbits(cls.bit_count())
        return [cls(randbits()) for _ in range(count)]

    def refresh_masks(self) -> None:
        new_masks = self.get_random_uints(self.order)
        for index, mask in enumerate(new_masks):
            self.masks[index] = self.unmasking_fn(self.masks[index], mask)
            self.masked_value = self.masking_fn(self.masked_value, mask)

    def unmask(self) -> BaseUint:
        masked_value = self.masked_value
        for mask in self.masks:
            masked_value = self.unmasking_fn(masked_value, mask)
        return masked_value

    def btoa(self) -> None:
        """
        Converts masked shares from boolean to arithmetic domain using
        the algorithm as published by Bettale et al. in their 2018 paper
        "Improved High-Order Conversion From Boolean to Arithmetic Masking"
        Link: https://eprint.iacr.org/2018/328.pdf
        """
        if self.domain != Domain.BOOLEAN:
            return
        uint = self.uint_class()

        def psi(masked: BaseUint, mask: BaseUint) -> BaseUint:
            return (masked ^ mask) - mask

        def convert(x: list[BaseUint], n_plus1: int) -> list[BaseUint]:
            n = n_plus1 - 1
            if n == 1:
                return [x[0] ^ x[1]]

            # --- Refresh masks ---
            new_masks = self.get_random_uints(len(x) - 1)
            for index, mask in enumerate(new_masks, start=1):
                x[index] ^= mask
                x[0] ^= mask

            # --- Gadget Ψ ---
            first_term = x[0] if (n - 1) & 1 else uint(0)
            y: list[BaseUint] = [first_term ^ psi(x[0], x[1])]
            y.extend([psi(x[0], x[i + 1]) for i in range(1, n)])

            # --- Recurse on the two halves ---
            first = convert(x[1:], n)
            second = convert(y, n)

            # --- Combine results ---
            out = [first[i] + second[i] for i in range(n - 2)]
            out.extend([first[n - 2], second[n - 2]])
            return out

        bool_shares = [self.masked_value, *self.masks, uint(0)]
        arith_shares = convert(bool_shares, self.share_count + 1)

        self.masked_value = arith_shares[0]
        self.masks = arith_shares[1:]
        self.domain = Domain.ARITHMETIC
        self.masking_fn = opr.sub
        self.unmasking_fn = opr.add


class MaskedUint8(BaseMaskedUint):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint8


class MaskedUint32(BaseMaskedUint):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint32


class MaskedUint64(BaseMaskedUint):
    @staticmethod
    def uint_class() -> t.Type[BaseUint]:
        return Uint64
