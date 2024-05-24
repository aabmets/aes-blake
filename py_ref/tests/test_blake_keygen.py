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


__all__ = [
	"fixture_blank_keygen",
	"test_mix_method",
	"test_mix_into_state",
	"test_permute",
	"test_set_params_digest_ctx_domain",
	"test_set_params_derive_keys_domain",
	"test_set_params_compute_chk_domain",
	"test_set_params_last_round_domain",
	"test_set_params_block_index",
	"test_compute_bib",
	"test_digest_context",
	"test_compress_digest_ctx_domain",
	"test_compress_derive_keys_domain",
	"test_compress_compute_chk_domain",
	"test_derive_keys",
	"test_normal_init"
]


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
		assert keygen.state[i].value == 0x10
	for i in [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15]:
		assert keygen.state[i].value == 0


def test_set_params_derive_keys_domain(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_params(domain=KDFDomain.DERIVE_KEYS)
	for i in range(8, 12):
		assert keygen.state[i].value == 0x20
	for i in [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15]:
		assert keygen.state[i].value == 0


def test_set_params_compute_chk_domain(blank_keygen):
	keygen = blank_keygen.clone()
	keygen.set_params(domain=KDFDomain.COMPUTE_CHK)
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
		0x4066EEF0, 0xA932B6BE, 0x3F996FD7, 0x71078506,
		0x5B206B6C, 0x3A7C157E, 0x3CCA8E2D, 0x1FDFC10B,
		0x3E7922CD, 0x7F333E4F, 0x2470DFDB, 0xB60C79AF,
		0x90D4BB1D, 0xA8FC153F, 0x68665CAA, 0xDDEB6721,
	]
	for i in range(16):
		assert state[i].value == expected[i]


def test_compress_digest_ctx_domain(blank_keygen):
	keygen = blank_keygen.clone()
	message = utils.bytes_to_uint32_vector(data=b'', size=16)

	keygen.compress(message, counter=0xABCDEF, domain=KDFDomain.DIGEST_CTX)
	expected = [
		0x7E084F83, 0x32B3B75F, 0x6A3FE28B, 0x6D5A0C44,
		0xE14DB6D2, 0xD434C21B, 0xF04DC021, 0xA184F5A6,
		0xD8896AF3, 0x39579F96, 0xDB4C0F76, 0x56A63EC7,
		0xC6B5EF3C, 0xE29CB1AC, 0xDF5F01DB, 0x21D43EDC,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]


def test_compress_derive_keys_domain(blank_keygen):
	keygen = blank_keygen.clone()
	message = utils.bytes_to_uint32_vector(data=b'', size=16)

	keygen.compress(message, counter=0xABCDEF, domain=KDFDomain.DERIVE_KEYS)
	expected = [
		0xF2976620, 0x0C4502FB, 0xDB1DF282, 0xBA66F35E,
		0x177E6104, 0xBBD4D067, 0xDB5FA814, 0x5B94AC47,
		0x7BCC422B, 0x27B60B54, 0x82FBDE62, 0x26340A1E,
		0x0B55B157, 0x915E8F1E, 0x750D7DCA, 0xB092C99E,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]


def test_compress_compute_chk_domain(blank_keygen):
	keygen = blank_keygen.clone()
	message = utils.bytes_to_uint32_vector(data=b'', size=16)

	keygen.compress(message, counter=0xABCDEF, domain=KDFDomain.COMPUTE_CHK)
	expected = [
		0x03964028, 0x1944D8D6, 0x80CB0A4B, 0xC73D1113,
		0x47FA60EB, 0xF7BED8A3, 0xDD26012A, 0xFC0909D4,
		0x3C5BDA7B, 0xAD09ECAB, 0xC4CCD04F, 0xB9FE611F,
		0xDE288819, 0x95EB02A0, 0x9462CEE3, 0x17EE128A,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]


def test_derive_keys(blank_keygen):
	keygen = blank_keygen.clone()
	for chunk in keygen.derive_keys(counter=0xFF):
		assert chunk == [0x51FC6266, 0x315B5CD0, 0x3B3E2E1A, 0x17D115CB]
		break


def test_normal_init():
	keygen = BlakeKeyGen(key=b'\x00', nonce=b'', context=b'')
	expected = [
		0x36EA6F8E, 0xD1D96C15, 0xCDE0704D, 0x1C5BA81C,
		0x962AD8FE, 0x976D9DB4, 0x54997A13, 0xFDA31AAA,
		0x6A4AF383, 0x504F1BA2, 0xE7626812, 0x75EE97E0,
		0xD08A0BC8, 0x0F9690E7, 0x883A1E83, 0x09137F84,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]

	keygen = BlakeKeyGen(key=b'\x01', nonce=b'', context=b'')
	expected = [
		0x1A507B1D, 0x5322B0F5, 0x7CC05F76, 0x2DE26A09,
		0x3F04F36A, 0xA5D761F4, 0x6C1E2F82, 0xC4F5539B,
		0xAB195834, 0x9C4001A0, 0xA6327E94, 0x55DE1C72,
		0x2A3B9E39, 0xCF6E4950, 0x58056C49, 0x98B3ABDF,
	]
	for i in range(16):
		assert keygen.state[i].value == expected[i]
