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

import string
import itertools
import operator as opr
import typing as t
from abc import ABC, abstractmethod
from contextlib import contextmanager
from src.integers.expression_node import *

__all__ = ["IterNum", "BaseUint"]


T = t.TypeVar("T", bound="BaseUint")
ByteOrder = t.Literal["little", "big"]
IterNum = t.Union[t.Iterable[t.SupportsIndex], t.SupportsBytes]


class BaseUint(ABC):
    _exp_node: ExpressionNode | None = None
    _exp_nodes_enabled: bool = False
    _used_names: set[str] = set()
    _name_base = "unnamed"
    _name = "unnamed"

    @staticmethod
    @abstractmethod
    def bit_count() -> int: ...

    @staticmethod
    @abstractmethod
    def max_value() -> int: ...

    @property
    def value(self) -> int:
        return self._value

    @property
    def name(self) -> str:
        return self._name

    @property
    def hamming_weight(self) -> int:
        return self._value.bit_count()

    @value.setter
    def value(self, value: int) -> None:
        if isinstance(value, BaseUint):
            value = value.value
        elif not isinstance(value, int):
            raise TypeError(f"Cannot set {self.__class__.__name__} value from {value}")
        self._value = value & self.max_value()

    def __init__(self, value: int | BaseUint = 0, *, suffix: str = "") -> None:
        self.value = value.value if isinstance(value, BaseUint) else value
        if BaseUint._exp_nodes_enabled:
            self._name_base, self._name = self._generate_unique_name(suffix)
            if isinstance(value, BaseUint) and hasattr(value, '_exp_node'):
                self._exp_node = CopyNode(self._name, getattr(value, '_exp_node'))
            else:
                self._exp_node = VarNode(self._name, self._value)

    @classmethod
    def _generate_unique_name(cls, suffix: str = '') -> t.Tuple[str, str]:
        """Generates a unique variable name for the class."""
        for repeat in range(1, 4):
            for combo in itertools.product(string.ascii_uppercase, repeat=repeat):
                name_base = name = ''.join(combo)
                if name_base not in cls._used_names:
                    cls._used_names.add(name_base)
                    if suffix:
                        name += '_' + suffix
                    return name_base, name
        raise RuntimeError("Out of names")

    @classmethod
    def from_bytes(cls: t.Type[T], data: IterNum, *, byteorder: ByteOrder = "big") -> T:
        return cls(int.from_bytes(data, byteorder, signed=False))

    def to_bytes(self, *, byteorder: ByteOrder = "big") -> bytes:
        return self.value.to_bytes(self.bit_count() // 8, byteorder)

    def to_dict(self) -> dict:
        if BaseUint._exp_nodes_enabled and hasattr(self, '_exp_node'):
            return self._exp_node.to_dict()
        return {"type": "const", "value": self._value}

    def _operate(self, operator: t.Callable, other: int | BaseUint, cls: t.Type = None) -> t.Any:
        other_val = other.value if isinstance(other, BaseUint) else other
        if cls is None:
            cls = self.__class__
        result_val = operator(self._value, other_val)
        result = cls(result_val)
        if BaseUint._exp_nodes_enabled and isinstance(result, BaseUint):
            left_node = getattr(self, '_exp_node', VarNode(self._name, self._value))
            right_node = (
                getattr(other, '_exp_node')
                if isinstance(other, BaseUint)
                else ConstNode(other_val)
            )
            result._exp_node = BinaryOpNode(result._name, operator, left_node, right_node)
        return result

    def __index__(self) -> int:
        return self._value
    def __int__(self) -> int:
        return self._value
    def __str__(self) -> str:
        return str(self._value)

    def __add__(self, other: int | BaseUint) -> BaseUint:
        return self._operate(opr.add, other)
    def __sub__(self, other: int | BaseUint) -> BaseUint:
        return self._operate(opr.sub, other)
    def __mul__(self, other: int | BaseUint) -> BaseUint:
        return self._operate(opr.mul, other)
    def __pow__(self, other: int | BaseUint) -> BaseUint:
        return self._operate(opr.pow, other)
    def __mod__(self, other: int | BaseUint) -> BaseUint:
        return self._operate(opr.mod, other)
    def __and__(self, other: int | BaseUint) -> BaseUint:
        return self._operate(opr.and_, other)
    def __or__(self, other: int | BaseUint) -> BaseUint:
        return self._operate(opr.or_, other)
    def __xor__(self, other: int | BaseUint) -> BaseUint:
        return self._operate(opr.xor, other)

    def __neg__(self) -> BaseUint:
        return self._unary_op_helper(opr.neg, '-')
    def __invert__(self) -> BaseUint:
        return self._unary_op_helper(opr.invert, '~')
    def __rshift__(self, other: int) -> BaseUint:
        return self._shift_op_helper(opr.rshift, other)
    def __lshift__(self, other: int) -> BaseUint:
        return self._shift_op_helper(opr.lshift, other)

    def rotl(self, n: int) -> BaseUint:
        """Rotates bits out from the left and back into the right"""
        distance = n % self.bit_count()
        rs = self._value >> (self.bit_count() - distance)
        ls = self._value << distance
        res = (rs | ls) & self.max_value()
        return self.__class__(res)

    def rotr(self, n: int) -> BaseUint:
        """Rotates bits out from the right and back into the left"""
        distance = n % self.bit_count()
        rs = self._value >> distance
        ls = self._value << (self.bit_count() - distance)
        res = (rs | ls) & self.max_value()
        return self.__class__(res)

    def __eq__(self, other: int | BaseUint) -> bool:
        return self._operate(opr.eq, other, bool)
    def __ne__(self, other: int | BaseUint) -> bool:
        return self._operate(opr.ne, other, bool)
    def __gt__(self, other: int | BaseUint) -> bool:
        return self._operate(opr.gt, other, bool)
    def __lt__(self, other: int | BaseUint) -> bool:
        return self._operate(opr.lt, other, bool)
    def __ge__(self, other: int | BaseUint) -> bool:
        return self._operate(opr.ge, other, bool)
    def __le__(self, other: int | BaseUint) -> bool:
        return self._operate(opr.le, other, bool)

    def _shift_op_helper(self, operator: t.Callable[[int, int], int], distance: int) -> BaseUint:
        result_val = operator(self._value, distance)
        result = self.__class__(result_val)
        if BaseUint._exp_nodes_enabled:
            exp_node = getattr(self, '_exp_node', ConstNode(self._value))
            result._exp_node = BinaryOpNode(result._name, operator, exp_node, ConstNode(distance))
        return result

    def _unary_op_helper(self, operator: t.Callable[[int], int], symbol: str) -> BaseUint:
        result_val = operator(self._value) & self.max_value()
        result = self.__class__(result_val)
        if BaseUint._exp_nodes_enabled:
            exp_node = getattr(self, '_exp_node', ConstNode(self._value))
            result._exp_node = UnaryOpNode(result._name, symbol, exp_node)
        return result

    def evaluate(self) -> int:
        if BaseUint._exp_nodes_enabled and hasattr(self, '_exp_node'):
            return self._exp_node.evaluate()
        raise RuntimeError(
            "Cannot evaluate expression nodes outside "
            "of equations_logger context manager"
        )

    def get_equation(self) -> str:
        if BaseUint._exp_nodes_enabled and hasattr(self, '_exp_node'):
            return self._exp_node.equation_str()
        raise RuntimeError(
            "Cannot get algebraic equation outside "
            "of equations_logger context manager"
        )

    def get_assignments(self) -> str:
        if BaseUint._exp_nodes_enabled and hasattr(self, '_exp_node'):
            return self._exp_node.assignments_str()
        raise RuntimeError(
            "Cannot get variable assignments outside "
            "of equations_logger context manager"
        )

    def debug_math(self, location: str) -> None:
        if BaseUint._exp_nodes_enabled and hasattr(self, '_exp_node'):
            print()
            print('-' * 80)
            print(f"Location:".ljust(13, ' '), location)
            print(f"Assignments:".ljust(13, ' '), self.get_assignments())
            print(f"Equation:".ljust(13, ' '), self.get_equation())

    @classmethod
    @contextmanager
    def math_debugger(cls):
        old = cls._exp_nodes_enabled
        cls._exp_nodes_enabled = True
        try:
            yield
        finally:
            cls._used_names.clear()
            cls._exp_nodes_enabled = old
