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

import pytest

from src.aes_blake import AESBlake, BlockSize

__all__ = [
    "flip_bit",
    "test_aes_blake_128",
    "test_aes_blake_128_bad_args",
    "test_aes_blake_256",
    "test_aes_blake_256_bad_args",
    "test_aes_blake_384",
    "test_aes_blake_384_bad_args",
    "test_aes_blake_512",
    "test_aes_blake_512_bad_args",
]


def flip_bit(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


def test_aes_blake_128():
    key = context = nonce = header = b"\xff"
    plaintext = bytes(x for x in range(8))
    aes = AESBlake(key, context, BlockSize.BITS_128)
    ciphertext, tag = aes.encrypt(plaintext, nonce, header)

    assert len(ciphertext) == 16 and len(tag) == 16
    assert ciphertext.startswith(b"\x3e\xca\x7c\x28")
    assert ciphertext.endswith(b"\x47\x9c\x5e\xf5")
    assert tag.startswith(b"\x51\x69\xad\x8a")
    assert tag.endswith(b"\x27\xd4\x6c\xa9")

    recovered_plaintext = aes.decrypt(ciphertext, tag, nonce, header)
    assert recovered_plaintext == plaintext


def test_aes_blake_128_bad_args():
    key = context = nonce = header = b"\xff"
    plaintext = bytes(x for x in range(8))
    aes = AESBlake(key, context, BlockSize.BITS_128)
    ciphertext, tag = aes.encrypt(plaintext, nonce, header)

    bad_args = [
        [flip_bit(key), context, ciphertext, tag, nonce, header],
        [key, flip_bit(context), ciphertext, tag, nonce, header],
        [key, context, flip_bit(ciphertext), tag, nonce, header],
        [key, context, ciphertext, flip_bit(tag), nonce, header],
        [key, context, ciphertext, tag, flip_bit(nonce), header],
        [key, context, ciphertext, tag, nonce, flip_bit(header)],
    ]
    for args in bad_args:
        context, key = args.pop(1), args.pop(0)
        aes = AESBlake(key, context, BlockSize.BITS_128)
        with pytest.raises(ValueError, match="Failed to verify auth tag!"):
            aes.decrypt(*args)

    for bad_size in [BlockSize.BITS_256, BlockSize.BITS_384, BlockSize.BITS_512]:
        aes = AESBlake(key, context, bad_size)
        with pytest.raises(ValueError, match="Invalid ciphertext length!"):
            aes.decrypt(ciphertext, tag, nonce, header)
        with pytest.raises(ValueError, match="Failed to verify auth tag!"):
            correct_len = ciphertext * bad_size.value
            aes.decrypt(correct_len, tag, nonce, header)


def test_aes_blake_256():
    key = context = nonce = header = b"\xff"
    plaintext = bytes(x for x in range(8))
    aes = AESBlake(key, context, BlockSize.BITS_256)
    ciphertext, tag = aes.encrypt(plaintext, nonce, header)

    assert len(ciphertext) == 32 and len(tag) == 32
    assert ciphertext.startswith(b"\x29\xdd\xc8\xb1")
    assert ciphertext.endswith(b"\x65\x4a\xb6\x96")
    assert tag.startswith(b"\x27\x27\xb5\x0f")
    assert tag.endswith(b"\xc4\x4f\x9a\xdb")

    recovered_plaintext = aes.decrypt(ciphertext, tag, nonce, header)
    assert recovered_plaintext == plaintext


def test_aes_blake_256_bad_args():
    key = context = nonce = header = b"\xff"
    plaintext = bytes(x for x in range(8))
    aes = AESBlake(key, context, BlockSize.BITS_256)
    ciphertext, tag = aes.encrypt(plaintext, nonce, header)

    bad_args = [
        [flip_bit(key), context, ciphertext, tag, nonce, header],
        [key, flip_bit(context), ciphertext, tag, nonce, header],
        [key, context, flip_bit(ciphertext), tag, nonce, header],
        [key, context, ciphertext, flip_bit(tag), nonce, header],
        [key, context, ciphertext, tag, flip_bit(nonce), header],
        [key, context, ciphertext, tag, nonce, flip_bit(header)],
    ]
    for args in bad_args:
        context, key = args.pop(1), args.pop(0)
        aes = AESBlake(key, context, BlockSize.BITS_256)
        with pytest.raises(ValueError, match="Failed to verify auth tag!"):
            aes.decrypt(*args)

    for bad_size in [BlockSize.BITS_128, BlockSize.BITS_384, BlockSize.BITS_512]:
        aes = AESBlake(key, context, bad_size)
        if bad_size != BlockSize.BITS_128:
            with pytest.raises(ValueError, match="Invalid ciphertext length!"):
                aes.decrypt(ciphertext, tag, nonce, header)
        with pytest.raises(ValueError, match="Failed to verify auth tag!"):
            correct_len = ciphertext * bad_size.value
            aes.decrypt(correct_len, tag, nonce, header)


def test_aes_blake_384():
    key = context = nonce = header = b"\xff"
    plaintext = bytes(x for x in range(8))
    aes = AESBlake(key, context, BlockSize.BITS_384)
    ciphertext, tag = aes.encrypt(plaintext, nonce, header)

    assert len(ciphertext) == 48 and len(tag) == 48
    assert ciphertext.startswith(b"\x0d\x1d\x39\x16")
    assert ciphertext.endswith(b"\x6e\x97\x5b\xaf")
    assert tag.startswith(b"\xef\x78\x52\xcc")
    assert tag.endswith(b"\xf9\xf0\x28\x41")

    recovered_plaintext = aes.decrypt(ciphertext, tag, nonce, header)
    assert recovered_plaintext == plaintext


def test_aes_blake_384_bad_args():
    key = context = nonce = header = b"\xff"
    plaintext = bytes(x for x in range(8))
    aes = AESBlake(key, context, BlockSize.BITS_384)
    ciphertext, tag = aes.encrypt(plaintext, nonce, header)

    bad_args = [
        [flip_bit(key), context, ciphertext, tag, nonce, header],
        [key, flip_bit(context), ciphertext, tag, nonce, header],
        [key, context, flip_bit(ciphertext), tag, nonce, header],
        [key, context, ciphertext, flip_bit(tag), nonce, header],
        [key, context, ciphertext, tag, flip_bit(nonce), header],
        [key, context, ciphertext, tag, nonce, flip_bit(header)],
    ]
    for args in bad_args:
        context, key = args.pop(1), args.pop(0)
        aes = AESBlake(key, context, BlockSize.BITS_384)
        with pytest.raises(ValueError, match="Failed to verify auth tag!"):
            aes.decrypt(*args)

    for bad_size in [BlockSize.BITS_128, BlockSize.BITS_256, BlockSize.BITS_512]:
        aes = AESBlake(key, context, bad_size)
        if bad_size not in [BlockSize.BITS_128, BlockSize.BITS_256]:
            with pytest.raises(ValueError, match="Invalid ciphertext length!"):
                aes.decrypt(ciphertext, tag, nonce, header)
        with pytest.raises(ValueError, match="Failed to verify auth tag!"):
            correct_len = ciphertext * bad_size.value
            aes.decrypt(correct_len, tag, nonce, header)


def test_aes_blake_512():
    key = context = nonce = header = b"\xff"
    plaintext = bytes(x for x in range(8))
    aes = AESBlake(key, context, BlockSize.BITS_512)
    ciphertext, tag = aes.encrypt(plaintext, nonce, header)

    assert len(ciphertext) == 64 and len(tag) == 64
    assert ciphertext.startswith(b"\xd7\x4b\xa8\xdb")
    assert ciphertext.endswith(b"\x96\xb1\xe0\x12")
    assert tag.startswith(b"\x72\x18\x83\x64")
    assert tag.endswith(b"\x61\x42\x11\xb6")

    recovered_plaintext = aes.decrypt(ciphertext, tag, nonce, header)
    assert recovered_plaintext == plaintext


def test_aes_blake_512_bad_args():
    key = context = nonce = header = b"\xff"
    plaintext = bytes(x for x in range(8))
    aes = AESBlake(key, context, BlockSize.BITS_512)
    ciphertext, tag = aes.encrypt(plaintext, nonce, header)

    bad_args = [
        [flip_bit(key), context, ciphertext, tag, nonce, header],
        [key, flip_bit(context), ciphertext, tag, nonce, header],
        [key, context, flip_bit(ciphertext), tag, nonce, header],
        [key, context, ciphertext, flip_bit(tag), nonce, header],
        [key, context, ciphertext, tag, flip_bit(nonce), header],
        [key, context, ciphertext, tag, nonce, flip_bit(header)],
    ]
    for args in bad_args:
        context, key = args.pop(1), args.pop(0)
        aes = AESBlake(key, context, BlockSize.BITS_512)
        with pytest.raises(ValueError, match="Failed to verify auth tag!"):
            aes.decrypt(*args)

    for bad_size in [BlockSize.BITS_128, BlockSize.BITS_256, BlockSize.BITS_384]:
        aes = AESBlake(key, context, bad_size)
        with pytest.raises(ValueError, match="Failed to verify auth tag!"):
            correct_len = ciphertext * bad_size.value
            aes.decrypt(correct_len, tag, nonce, header)
