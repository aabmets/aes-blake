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
from copy import deepcopy
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

    @property
    def shares(self) -> list[BaseUint]:
        for index, uint in enumerate([self.masked_value, *self.masks]):
            self._shares[index] = uint
        return self._shares

    @shares.setter
    def shares(self, shares: list[BaseUint]) -> None:
        for index, uint in enumerate(shares):
            self._shares[index] = uint
        self.masked_value = shares[0]
        self.masks = shares[1:]

    def __init__(self, value: int | BaseUint, order: int, domain: Domain) -> None:
        assert value >= 0, "Value must be greater than or equal to zero"
        assert order > 0, "Order must be greater than zero"
        assert domain in Domain, "Domain must be one of the defined domains"

        self.order = order
        self.domain = domain
        self.share_count = order + 1
        self.masking_fn = opr.xor if domain == Domain.BOOLEAN else opr.sub
        self.unmasking_fn = opr.xor if domain == Domain.BOOLEAN else opr.add
        self.masks = self.get_random_uints(order)
        self.masked_value: BaseUint = self.uint_class()(value)
        self._shares: list[BaseUint] = [self.masked_value, *self.masks]
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

    def create(self, shares: list[BaseUint], domain: Domain = None, clone: bool = True) -> BaseMaskedUint:
        mv = deepcopy(self) if clone else self
        mv.shares = shares
        mv.domain = domain or mv.domain
        mv.masking_fn = opr.xor if mv.domain == Domain.BOOLEAN else opr.sub
        mv.unmasking_fn = opr.xor if mv.domain == Domain.BOOLEAN else opr.add
        return mv

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
        self.create(arith_shares, Domain.ARITHMETIC, clone=False)

    def validate_binary_operands(self, other: BaseMaskedUint, domain: Domain, operation: str) -> None:
        if not isinstance(other, BaseMaskedUint):
            raise TypeError("Operands must be instances of BaseMaskedUint")
        if self.domain != domain or other.domain != domain:
            raise ValueError(f"{operation} is only defined for {domain.name}-masked values")
        if self.order != other.order:
            raise ValueError("Operands must have the same masking order")
        if self.uint_class() is not other.uint_class():
            raise TypeError("Operands must use the same uint width")

    def validate_unary_operand(self, domain: Domain, operation: str, distance: int = None) -> None:
        if self.domain != domain:
            raise ValueError(f"{operation} is only defined for {domain.name}-masked values")
        if distance and distance < 1:
            raise ValueError("Distance must be greater than or equal to one")

    def _and_mul_helper(self, other: BaseMaskedUint, operator: t.Callable, domain: Domain) -> BaseMaskedUint:
        """
        Performs multiplication/AND logic on two masked shares using the DOM-independent
        secure gadget as described by Gross et al. in “Domain-Oriented Masking” (CHES 2016).
        Link: https://eprint.iacr.org/2016/486.pdf
        """
        self.validate_binary_operands(other, domain, operator.__name__)

        x, y = self.shares, other.shares
        out = [operator(x[i], y[i]) for i in range(self.share_count)]

        pair_count = self.share_count * self.order // 2
        rand_vals = iter(self.get_random_uints(pair_count))

        for i in range(self.order):
            for j in range(i + 1, self.share_count):
                rand = next(rand_vals)
                o_ji = operator(x[j], y[i])
                o_ij = operator(x[i], y[j])
                p_ji = self.masking_fn(o_ji, rand)
                p_ij = self.unmasking_fn(o_ij, rand)
                out[i] = self.unmasking_fn(out[i], p_ij)
                out[j] = self.unmasking_fn(out[j], p_ji)

        return self.create(out)

    def __and__(self, other: BaseMaskedUint) -> BaseMaskedUint:
        return self._and_mul_helper(other, opr.and_, Domain.BOOLEAN)

    def __mul__(self, other: "BaseMaskedUint") -> "BaseMaskedUint":
        return self._and_mul_helper(other, opr.mul, Domain.ARITHMETIC)

    def __or__(self, other: BaseMaskedUint) -> BaseMaskedUint:
        self.validate_binary_operands(other, Domain.BOOLEAN, "__or__")
        x, y, out = self.shares, other.shares, (self & other).shares
        for i in range(self.share_count):
            out[i] ^= x[i] ^ y[i]
        return self.create(out)

    def _xor_add_sub_helper(self, other: BaseMaskedUint, domain: Domain, operator: t.Callable) -> BaseMaskedUint:
        self.validate_binary_operands(other, domain, operator.__name__)
        x, out = other.shares, deepcopy(self).shares
        for i in range(self.share_count):
            out[i] = operator(out[i], x[i])
        return self.create(out)

    def __xor__(self, other: BaseMaskedUint) -> BaseMaskedUint:
        return self._xor_add_sub_helper(other, Domain.BOOLEAN, opr.xor)

    def __add__(self, other: BaseMaskedUint) -> BaseMaskedUint:
        return self._xor_add_sub_helper(other, Domain.ARITHMETIC, opr.add)

    def __sub__(self, other: BaseMaskedUint) -> BaseMaskedUint:
        return self._xor_add_sub_helper(other, Domain.ARITHMETIC, opr.sub)

    def __invert__(self) -> BaseMaskedUint:
        self.validate_unary_operand(Domain.BOOLEAN, "__invert__")
        self.masked_value = ~self.masked_value
        return self

    def _shift_rotate_helper(self, operation: str, distance: int = None) -> BaseMaskedUint:
        self.validate_unary_operand(Domain.BOOLEAN, operation, distance)
        self.masked_value = getattr(self.masked_value, operation)(distance)
        for index, mask in enumerate(self.masks):
            self.masks[index] = getattr(mask, operation)(distance)
        return self

    def __rshift__(self, distance: int) -> BaseMaskedUint:
        return self._shift_rotate_helper("__rshift__", distance)

    def __lshift__(self, distance: int) -> BaseMaskedUint:
        return self._shift_rotate_helper("__lshift__", distance)

    def rotr(self, distance: int) -> BaseMaskedUint:
        return self._shift_rotate_helper("rotr", distance)

    def rotl(self, distance: int) -> BaseMaskedUint:
        return self._shift_rotate_helper("rotl", distance)


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
