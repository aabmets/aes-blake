#
#   MIT License
#   
#   Copyright (c) 2024, Mattias Aabmets
#   
#   The contents of this file are subject to the terms and conditions defined in the License.
#   You may not use, modify, or distribute this file except in compliance with the License.
#   
#   SPDX-License-Identifier: MIT
#
import re
from rich.console import Console
from .uint import BaseUint


__all__ = [
	"pretty_print_bin",
	"pretty_print_hex"
]


_console = Console()


def pretty_print_bin(
		uint: BaseUint,
		color_0: str = "blue",
		color_1: str = "red",
		end='\n'
) -> None:
	bb_list = []
	for bb_str in uint.binary_bytes:
		first_color = color_0 if bb_str.startswith('0') else color_1
		bb_str = re.sub(r"1(0)", rf"1[{color_0}]\1", bb_str)
		bb_str = re.sub(r"0(1)", rf"0[{color_1}]\1", bb_str)
		bb_str = f"[{first_color}]{bb_str}"
		bb_list.append(bb_str)
	concat_bb = '  '.join(bb_list)
	_console.print(concat_bb, end=end)


def pretty_print_hex(
		uint: BaseUint,
		color: str = "green",
		end='\n'
) -> None:
	hex_list = []
	for bb_str in uint.binary_bytes:
		value = int(bb_str, base=2)
		hex_int = int(hex(value), 16)
		hex_list.append(f"{hex_int:02X}")
	concat_hex = ' '.join(hex_list)
	hex_str = f"[{color}]{concat_hex}"
	_console.print(hex_str, end=end)
