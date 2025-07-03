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
import secrets
import typing as t
import operator as opr
from functools import partial
from copy import deepcopy
from abc import ABC, abstractmethod
from enum import Enum
from src.integers.base_uint import *

__all__ = ["Domain", "BaseMaskedUint"]


class Domain(Enum):
    BOOLEAN = 0
    ARITHMETIC = 1


class BaseMaskedUint(ABC):
    @staticmethod
    @abstractmethod
    def uint_class() -> t.Type[BaseUint]: ...

    @staticmethod
    @abstractmethod
    def bit_length() -> int: ...

    @staticmethod
    @abstractmethod
    def max_value() -> int: ...

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

    @property
    def hamming_weights(self) -> list[int]:
        return [s.hamming_weight for s in self.shares]

    def __init__(
            self,
            value: int | BaseUint,
            domain: Domain = Domain.BOOLEAN,
            order: int = int(os.getenv("MASKING_ORDER", 3)),
            *,
            automatic_domain_conversion: bool = True
    ) -> None:
        assert value >= 0, "Value must be greater than or equal to zero"
        assert order > 0, "Order must be greater than zero"
        assert domain in Domain, "Domain must be one of the defined domains"

        self.order = order
        self.domain = domain
        self.auto_domain = automatic_domain_conversion
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
        randbits = lambda: secrets.randbits(cls.bit_length())
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

    def btoa(self) -> BaseMaskedUint:
        """
        Converts masked shares from boolean to arithmetic domain using
        the affine psi recursive decomposition method of Bettale et al.,
        "Improved High-Order Conversion From Boolean to Arithmetic Masking"
        Link: https://eprint.iacr.org/2018/328.pdf
        """
        if self.domain != Domain.BOOLEAN:
            return self
        uint = self.uint_class()

        def psi(masked: BaseUint, mask: BaseUint) -> BaseUint:
            return (masked ^ mask) - mask

        def convert(x: list[BaseUint], n_plus1: int) -> list[BaseUint]:
            n = n_plus1 - 1
            if n == 1:
                return [x[0] ^ x[1]]

            new_masks = self.get_random_uints(len(x) - 1)
            for index, mask in enumerate(new_masks, start=1):
                x[index] ^= mask
                x[0] ^= mask

            first_term = x[0] if (n - 1) & 1 else uint(0)
            y: list[BaseUint] = [first_term ^ psi(x[0], x[1])]
            y.extend([psi(x[0], x[i + 1]) for i in range(1, n)])

            first = convert(x[1:], n)
            second = convert(y, n)

            out = [first[i] + second[i] for i in range(n - 2)]
            out.extend([first[n - 2], second[n - 2]])
            return out

        bool_shares = [self.masked_value, *self.masks, uint(0)]
        arith_shares = convert(bool_shares, self.share_count + 1)
        return self.create(arith_shares, Domain.ARITHMETIC, clone=False)

    def atob(self) -> BaseMaskedUint:
        """
        Converts masked shares from arithmetic to Boolean domain using
        the high-order recursive carry-save-adder method of Liu et al.,
        “A Low-Latency High-Order Arithmetic to Boolean Masking Conversion”
        Link: https://eprint.iacr.org/2024/045.pdf
        """
        if self.domain != Domain.ARITHMETIC:
            return self
        bmu_tuple = tuple[BaseMaskedUint, BaseMaskedUint]

        def csa(x: BaseMaskedUint, y: BaseMaskedUint, z: BaseMaskedUint) -> bmu_tuple:
            a = x ^ y
            s = a ^ z
            w = x ^ z
            v = a & w
            c = x ^ v
            return s, c << 1

        def csa_tree(vals: list[BaseMaskedUint]) -> bmu_tuple:
            if len(vals) == 3:
                return csa(vals[0], vals[1], vals[2])
            s, c = csa_tree(vals[:-1])
            return csa(s, c, vals[-1])

        def ksa(a: BaseMaskedUint, b: BaseMaskedUint) -> BaseMaskedUint:
            p = a ^ b
            g = a & b
            rounds = [1, 2, 4, 8, 16, 32, 64]
            bit_length = self.uint_class().bit_length()
            for dist in [n for n in rounds if n < bit_length]:
                g_shift = deepcopy(g) << dist
                p_shift = deepcopy(p) << dist
                g = g ^ (p & g_shift)
                p = p & p_shift
            return g << 1

        cls = partial(self.__class__, order=self.order, domain=Domain.BOOLEAN)
        shares = [cls(v) for v in [self.masked_value, *self.masks]]

        if self.share_count == 2:
            s_, c_ = shares[0], shares[1]
        else:
            s_, c_ = csa_tree(shares)

        result = s_ ^ c_ ^ ksa(s_, c_)
        return self.create(result.shares, Domain.BOOLEAN, clone=False)

    def ensure_expected_domain(self, expected_domain: Domain) -> None:
        if self.domain != expected_domain:
            if self.domain == Domain.BOOLEAN:
                self.btoa()
            elif self.domain == Domain.ARITHMETIC:
                self.atob()

    def validate_binary_operands(self, other: BaseMaskedUint, domain: Domain, operation: str) -> None:
        if not isinstance(other, BaseMaskedUint):
            raise TypeError("Operands must be instances of BaseMaskedUint")
        if self.order != other.order:
            raise ValueError("Operands must have the same masking order")
        if self.uint_class() is not other.uint_class():
            raise TypeError("Operands must use the same uint width")

        for operand in [self, other]:
            if operand.domain != domain and not operand.auto_domain:
                raise ValueError(f"{operation} is only defined for {domain.name}-masked values")
            operand.ensure_expected_domain(domain)

    def validate_unary_operand(self, domain: Domain, operation: str, distance: int = None) -> None:
        if distance and distance < 1:
            raise ValueError("Distance must be greater than or equal to one")
        if self.domain != domain and not self.auto_domain:
            raise ValueError(f"{operation} is only defined for {domain.name}-masked values")
        self.ensure_expected_domain(domain)

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

    def __neg__(self) -> BaseMaskedUint:
        self.validate_unary_operand(Domain.ARITHMETIC, "__neg__")
        self.shares = [-s for s in self.shares]
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

    # for pytest only
    def __eq__(self, other: BaseUint | int) -> bool:
        return self.unmask() == other
    def __ne__(self, other: BaseUint | int) -> bool:
        return self.unmask() != other
    def __gt__(self, other: BaseUint | int) -> bool:
        return self.unmask() > other
    def __lt__(self, other: BaseUint | int) -> bool:
        return self.unmask() < other
    def __ge__(self, other: BaseUint | int) -> bool:
        return self.unmask() >= other
    def __le__(self, other: BaseUint | int) -> bool:
        return self.unmask() <= other
