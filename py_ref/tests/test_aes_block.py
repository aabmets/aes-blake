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
import pytest
from src.aes_block import AESBlock
from src.blake_keygen import BlakeKeyGen
from src.aes_sbox import SBox
from src.uint import Uint8


@pytest.fixture(name="preset_block", scope="function")
def fixture_internal_state() -> AESBlock:
	keygen = BlakeKeyGen()
	data = [
		0x87, 0xF2, 0x4D, 0x97,
		0x6E, 0x4C, 0x90, 0xEC,
		0x46, 0xE7, 0x4A, 0xC3,
		0xA6, 0x8C, 0xD8, 0x95,
	]
	return AESBlock(keygen, data, index=0)


def test_aes_block_init():
	keygen = BlakeKeyGen()
	block = AESBlock(keygen, [0] * 16, index=0)
	for uint8 in block.vector:
		assert uint8.value == 0

	assert len(block.keys) == 11
	for key_set in block.keys:
		assert len(key_set) == 16


def test_aes_block_encrypt_block(preset_block):
	values = [obj.value for obj in preset_block.vector]
	assert values == [
		0x87, 0xF2, 0x4D, 0x97,
		0x6E, 0x4C, 0x90, 0xEC,
		0x46, 0xE7, 0x4A, 0xC3,
		0xA6, 0x8C, 0xD8, 0x95,
	]
	preset_block.encrypt_block()
	values = [obj.value for obj in preset_block.vector]
	assert values == [
		0x37, 0xE3, 0xDD, 0x3E,
		0x99, 0x1D, 0xA5, 0xD0,
		0xB1, 0x86, 0xDF, 0x60,
		0x1A, 0xA2, 0x77, 0x4F,
	]
	preset_block.decrypt_block()
	values = [obj.value for obj in preset_block.vector]
	assert values == [
		0x87, 0xF2, 0x4D, 0x97,
		0x6E, 0x4C, 0x90, 0xEC,
		0x46, 0xE7, 0x4A, 0xC3,
		0xA6, 0x8C, 0xD8, 0x95,
	]


def test_aes_block_mix_columns(preset_block):
	preset_block.mix_columns()
	values = [obj.value for obj in preset_block.vector]
	assert values == [
		0xC2, 0x38, 0x4D, 0x18,
		0x74, 0xB1, 0x36, 0xAD,
		0x37, 0x8E, 0x6B, 0xFA,
		0x95, 0x43, 0x25, 0x94
	]
	preset_block.inv_mix_columns()
	values = [obj.value for obj in preset_block.vector]
	assert values == [
		0x87, 0xF2, 0x4D, 0x97,
		0x6E, 0x4C, 0x90, 0xEC,
		0x46, 0xE7, 0x4A, 0xC3,
		0xA6, 0x8C, 0xD8, 0x95,
	]


def test_aes_block_shift_rows(preset_block):
	preset_block.shift_rows()
	values = [obj.value for obj in preset_block.vector]
	assert values == [
		0x87, 0x4C, 0x4A, 0x95,
		0x6E, 0xE7, 0xD8, 0x97,
		0x46, 0x8C, 0x4D, 0xEC,
		0xA6, 0xF2, 0x90, 0xC3,
	]
	preset_block.inv_shift_rows()
	values = [obj.value for obj in preset_block.vector]
	assert values == [
		0x87, 0xF2, 0x4D, 0x97,
		0x6E, 0x4C, 0x90, 0xEC,
		0x46, 0xE7, 0x4A, 0xC3,
		0xA6, 0x8C, 0xD8, 0x95,
	]


def test_aes_block_add_round_key():
	keygen = BlakeKeyGen()
	block = AESBlock(keygen, [0] * 16, index=0)

	block.keys = [[Uint8(0xAB)] * 16]
	block.add_round_key(0)
	for uint8 in block.vector:
		assert uint8.value == 0xAB

	block.keys = [[Uint8(0x76)] * 16]
	block.add_round_key(0)
	for uint8 in block.vector:
		assert uint8.value == 0xDD


def test_aes_block_sub_bytes():
	keygen = BlakeKeyGen()
	block = AESBlock(keygen, [0] * 16, index=0)

	expected_values = [0x63, 0xFB, 0x0F, 0x76, 0x38]
	for exp_val in expected_values:
		block.sub_bytes(SBox.ENC)
		for i in range(16):
			assert block.vector[i].value == exp_val

	expected_values.reverse()
	for exp_val in expected_values:
		for i in range(16):
			assert block.vector[i].value == exp_val
		block.sub_bytes(SBox.DEC)
