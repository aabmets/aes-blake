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

import re
import typing as t

from rich.console import Console

from src.integers import *

__all__ = [
    "to_binary_bytes",
    "to_binary_string",
    "pretty_print_binary",
    "to_hex_bytes",
    "to_hex_string",
    "pretty_print_hex",
    "pretty_print_vector",
]


_console = Console()


def to_binary_bytes(uint: BaseUint | BaseMaskedUint) -> list[str]:
    uint = uint.unmask() if isinstance(uint, BaseMaskedUint) else uint
    bit_str = format(uint.value, f"0{uint.bit_length()}b")
    return [bit_str[i : i + 8] for i in range(0, len(bit_str), 8)]


def to_binary_string(uint: BaseUint | BaseMaskedUint, sep=" ") -> str:
    return sep.join(to_binary_bytes(uint))


def pretty_print_binary(
        uint: BaseUint,
        color_0="blue",
        color_1="red",
        end="\n"
) -> None:
    bb_list = []
    for bb_str in to_binary_bytes(uint):
        first_color = color_0 if bb_str.startswith("0") else color_1
        bb_str = re.sub(r"1(0)", rf"1[{color_0}]\1", bb_str)
        bb_str = re.sub(r"0(1)", rf"0[{color_1}]\1", bb_str)
        bb_str = f"[{first_color}]{bb_str}"
        bb_list.append(bb_str)
    concat_bb = "  ".join(bb_list)
    _console.print(concat_bb, end=end)


def to_hex_bytes(uint: BaseUint) -> list[str]:
    out = []
    for bb_str in to_binary_bytes(uint):
        out.append(f"{int(bb_str, base=2):02X}")
    return out


def to_hex_string(uint: BaseUint, sep=" ") -> str:
    return sep.join(to_hex_bytes(uint))


def pretty_print_hex(
        uint: BaseUint,
        color="green",
        end="\n",
        hex_prefix=False,
        comma=False
) -> None:
    sep = "" if hex_prefix else " "
    prefix = "0x" if hex_prefix else ""
    suffix = "," if comma else ""
    concat_hex = to_hex_string(uint, sep=sep)
    hex_str = f"[{color}]{prefix}{concat_hex}[/]{suffix}"
    _console.print(hex_str, end=end)


def pretty_print_vector(
        vector: t.Iterable[BaseUint],
        color="yellow",
        py_var=True
) -> None:
    if py_var:
        print(f"\nexpected = [")
    for i, uint in enumerate(vector):
        if i % 4 == 0 and i != 0:
            print()
        if py_var and i % 4 == 0:
            print("    ", end="")
        pretty_print_hex(uint, color, end="", hex_prefix=py_var, comma=py_var)
        if i not in [3, 7, 11, 15]:
            sep = " " if py_var else "  "
            print(sep, end="")
    if py_var:
        print("\n]")
    else:
        print()
