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
from src.blake_keygen import BlakeKeyGen, KDFDomain
from src.uint import Uint32, Uint64
from src import utils


@pytest.fixture(name="blank_keygen", scope="module")
def fixture_blank_keygen():
	keygen = BlakeKeyGen(key=b'', nonce=b'', context=b'')
	keygen.block_counter_base = Uint64(0)
	keygen.state = [Uint32(0)] * 16
	keygen.key = [Uint32(0)] * 16
	return keygen


def test_mix_method(blank_keygen):
	keygen = blank_keygen.clone()
	one, zero = Uint32(1), Uint32(0)

	keygen.mix(0, 4, 8, 12, one, zero)
	assert keygen.state[0].value == 0x00000011
	assert keygen.state[4].value == 0x20220202
	assert keygen.state[8].value == 0x11010100
	assert keygen.state[12].value == 0x11000100

	keygen.mix(0, 4, 8, 12, one, zero)
	assert keygen.state[0].value == 0x22254587
	assert keygen.state[4].value == 0xCB766A41
	assert keygen.state[8].value == 0xB9366396
	assert keygen.state[12].value == 0xA5213174

	for i in [1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15]:
		assert keygen.state[i].value == 0


def test_mix_into_state(blank_keygen):
	keygen = blank_keygen.clone()
	message = [Uint32(0)] * 16
	message[0] = Uint32(1)

	keygen.mix_into_state(message)
	expected = [
		0x00000121, 0x10001001, 0x10011010, 0x42242404,
		0x481480C8, 0x22422220, 0x00242202, 0x00622024,
		0x21110210, 0x28424626, 0x21111101, 0x02111101,
		0x01110001, 0x10100110, 0x26402604, 0x21001101,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]

	keygen.mix_into_state(message)
	expected = [
		0xCA362DD6, 0x137F4EC0, 0xC494A2BB, 0x646EF8F0,
		0x5F1FCA7F, 0x63736C1D, 0xF57FACCC, 0x30DDBBAE,
		0xFA440A96, 0x5DB9BE06, 0x94C333CD, 0x5C9DB225,
		0x7771670D, 0xA5F95EEA, 0x906D9D47, 0xCFA8B69A,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]


def test_permute(blank_keygen):
	keygen = blank_keygen.clone()
	message = [Uint32(c) for c in b"ABCDEFGHIJKLMNOP"]

	expected = [c for c in b"CGDKHAENBLMFJOPI"]
	message = keygen.permute(message)
	assert message == expected

	expected = [c for c in b"DEKMNCHOGFJALPIB"]
	message = keygen.permute(message)
	assert message == expected


def test_set_params_digest_ctx_domain(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_params(domain=KDFDomain.DIGEST_CTX)
	for i in range(8, 12):
		assert keygen.state[i].value == 0x20
	for i in [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15]:
		assert keygen.state[i].value == 0


def test_set_params_derive_keys_domain(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_params(domain=KDFDomain.DERIVE_KEY)
	for i in range(8, 12):
		assert keygen.state[i].value == 0x40
	for i in [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15]:
		assert keygen.state[i].value == 0x0


def test_set_params_last_round_domain(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_params(domain=KDFDomain.LAST_ROUND)
	for i in range(8, 12):
		assert keygen.state[i].value == 0x80
	for i in [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15]:
		assert keygen.state[i].value == 0x0


def test_set_params_block_index(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_params(counter=0xAABBCCDDEEFFAABB)
	for i in range(4):
		assert keygen.state[i].value == 0xBBAAFFEE + i
		assert keygen.state[i + 4].value == 0
		assert keygen.state[i + 8].value == 0
		assert keygen.state[i + 12].value == 0xDDCCBBAA


def test_compute_bib(blank_keygen):
	clone = blank_keygen.clone()

	bib = clone.compute_bcb(key=b'', nonce=b'')
	assert bib.value == 0x6363_6363_6363_6363

	bib = clone.compute_bcb(key=b'abcdefgh', nonce=b'12345678')
	assert bib.value == 0x7DB2_0578_77C8_98DE


def test_digest_context(blank_keygen):
	keygen = blank_keygen.clone()
	state = keygen.digest_context(b'')
	expected = [
		0xECB86367, 0xBFD3DD4A, 0xFF8285A7, 0xC22FF92C,
		0x859C06E4, 0x87B663A1, 0x84EA7C51, 0x4E0F2BB1,
		0xBDF19A21, 0x6C05C3EA, 0x2878731D, 0x44C08C32,
		0x3924C540, 0x0D51AF40, 0x178F244F, 0x1CA0EB45,
	]
	for i in range(16):
		assert state[i].value == expected[i]


def test_compress(blank_keygen):
	keygen = blank_keygen.clone()
	message = utils.bytes_to_uint32_vector(data=b'', size=16)

	keygen.compress(message, counter=0)
	expected = [
		0xF8D374A2, 0x8159CAF7, 0x8A917AD3, 0x335959CF,
		0xECD24E79, 0x7631BEB0, 0x16EE1CD4, 0xCC697A22,
		0xC72572FF, 0x54B46F14, 0xF55B9D12, 0x040943BD,
		0xF6F215ED, 0xF419CF01, 0x2EEACB51, 0x3047B2FC,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]

	keygen.compress(message, counter=1)
	expected = [
		0x668F50FF, 0xDBF71E3C, 0x5AB31C59, 0x63997B7A,
		0x297170CC, 0x4D9B6D6A, 0xDCFC2859, 0x65C3EB7C,
		0xBC48C590, 0xFA64C1F6, 0x087B143B, 0x8EE83077,
		0x5C214ADC, 0x372474BB, 0xEF3A0986, 0x69CE7695,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]


def test_derive_keys(blank_keygen):
	keygen = blank_keygen.clone()
	for chunk in keygen.derive_keys(counter=0xFF):
		assert chunk == [0xE89D66BC, 0x91CA531C, 0x3D812AC6, 0xFEF36AA9]
		break


def test_normal_init():
	keygen = BlakeKeyGen(key=b'\x00', nonce=b'', context=b'')
	expected = [
		0x12B6DC99, 0x283A4ECD, 0x71AFA85C, 0x3A26A768,
		0xC8C3F8F4, 0x30BAFFCC, 0x50900167, 0x2982986C,
		0xE7327C06, 0xD80CAF0A, 0xB847336D, 0xF7ECDCF6,
		0x09A4C33E, 0x3B73AA08, 0xEB6ECA6E, 0xF8A6167C,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]

	keygen = BlakeKeyGen(key=b'\x01', nonce=b'', context=b'')
	expected = [
		0x2426286B, 0x692F0422, 0xC8593E02, 0xC08ED732,
		0x3678BFAB, 0x4827F32D, 0x54EE3EDB, 0x262DA37C,
		0xA505FD5D, 0x4A69B53B, 0x891F8AA9, 0xCAAE2DED,
		0x649AEFCD, 0xBF955E8D, 0x3D401A37, 0x91F65838,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]
