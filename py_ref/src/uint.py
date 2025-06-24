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
import string
import itertools
import operator as opr
import typing as t
from abc import ABC, abstractmethod
from contextlib import contextmanager
from src.exp_node import *

__all__ = ["IterNum", "BaseUint", "Uint8", "Uint32", "Uint64"]


T = t.TypeVar("T", bound="BaseUint")
ByteOrder = t.Literal["little", "big"]
IterNum = t.Union[t.Iterable[t.SupportsIndex], t.SupportsBytes]


class BaseUint(ABC):
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

    @value.setter
    def value(self, value: int) -> None:
        if isinstance(value, BaseUint):
            value = value.value
        elif not isinstance(value, int):
            raise TypeError(f"Cannot set {self.__class__.__name__} value from {value}")
        self._value = value & self.max_value()

    def __init__(self, value: int | BaseUint = 0, *, suffix: str = "") -> None:
        self.value = value.value if isinstance(value, BaseUint) else value
        if self._exp_nodes_enabled:
            self._name_base, self._name = self._generate_unique_name(suffix)

    @classmethod
    def _generate_unique_name(cls, suffix: str = '') -> t.Tuple[str, str]:
        """Generates a unique variable name for the class."""
        chars = string.ascii_uppercase
        split_point = secrets.randbelow(len(chars))
        shuffled_chars = chars[split_point:] + chars[:split_point]

        for repeat in range(1, 4):
            for combo in itertools.product(shuffled_chars, repeat=repeat):
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

    def _operate(self, operator: t.Callable, other: int | BaseUint, cls: t.Type = None) -> t.Any:
        if isinstance(other, BaseUint):
            other = other.value
        if cls is None:
            cls = self.__class__
        value = operator(self._value, other)
        return cls(value)

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

    def __neg__(self) -> BaseUint:
        return self.__class__(-self.value & self.max_value())

    def __rshift__(self, other: int) -> BaseUint:
        return self.__class__(self._value >> other)

    def __lshift__(self, other: int) -> BaseUint:
        return self.__class__(self._value << other)

    def __invert__(self) -> BaseUint:
        return self.__class__(~self._value & self.max_value())

    def __index__(self) -> int:
        return self._value

    def __int__(self) -> int:
        return self._value

    def __str__(self) -> str:
        return str(self._value)

    def __del__(self):
        if name_base := getattr(self, "_name_base", False):
            BaseUint._used_names.discard(name_base)

    def rotl(self, n: int) -> BaseUint:
        """Rotates bits out from left and back into right"""
        distance = n % self.bit_count()
        rs = self._value >> (self.bit_count() - distance)
        ls = self._value << distance
        res = (rs | ls) & self.max_value()
        return self.__class__(res)

    def rotr(self, n: int) -> BaseUint:
        """Rotates bits out from right and back into left"""
        distance = n % self.bit_count()
        rs = self._value >> distance
        ls = self._value << (self.bit_count() - distance)
        res = (rs | ls) & self.max_value()
        return self.__class__(res)

    @classmethod
    @contextmanager
    def equations_logger(cls):
        old = cls._exp_nodes_enabled
        cls._exp_nodes_enabled = True
        try:
            yield
        finally:
            cls._exp_nodes_enabled = old


class Uint8(BaseUint):
    @staticmethod
    def bit_count() -> int:
        return 8

    @staticmethod
    def max_value() -> int:
        return 0xFF


class Uint32(BaseUint):
    @staticmethod
    def bit_count() -> int:
        return 32

    @staticmethod
    def max_value() -> int:
        return 0xFFFFFFFF


class Uint64(BaseUint):
    @staticmethod
    def bit_count() -> int:
        return 64

    @staticmethod
    def max_value() -> int:
        return 0xFFFFFFFFFFFFFFFF
