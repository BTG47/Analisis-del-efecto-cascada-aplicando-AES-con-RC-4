"""Tests de la ruta SIN padding, la que necesita el experimento de Diego."""

import pytest

from aes256 import (
    aes_decrypt,
    aes_decrypt_raw,
    aes_encrypt,
    aes_encrypt_raw,
)
from padding import pkcs7_pad, pkcs7_unpad

KEY = bytes(range(32))


@pytest.mark.parametrize("bad_len", [1, 15, 17, 31, 33])
def test_raw_rechaza_largos_no_multiplos(bad_len):
    with pytest.raises(ValueError):
        aes_encrypt_raw(b"x" * bad_len, KEY)
    with pytest.raises(ValueError):
        aes_decrypt_raw(b"x" * bad_len, KEY)


def test_raw_admite_entrada_vacia():
    assert aes_encrypt_raw(b"", KEY) == b""
    assert aes_decrypt_raw(b"", KEY) == b""


@pytest.mark.parametrize("n", [16, 32, 64, 256])
def test_raw_round_trip(n):
    data = bytes((i * 13) % 256 for i in range(n))
    assert aes_decrypt_raw(aes_encrypt_raw(data, KEY), KEY) == data


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 100])
def test_api_publica_es_padding_mas_raw(n):
    """aes_encrypt(x) == aes_encrypt_raw(pkcs7_pad(x)).

    Este test une las dos capas: si falla, el padding o el bloque están mal.
    """
    data = bytes((i * 11) % 256 for i in range(n))
    assert aes_encrypt(data, KEY) == aes_encrypt_raw(pkcs7_pad(data), KEY)


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 100])
def test_descifrado_publico_equivale_a_unpad_del_raw(n):
    data = bytes((i * 5) % 256 for i in range(n))
    cifrado = aes_encrypt(data, KEY)
    assert pkcs7_unpad(aes_decrypt_raw(cifrado, KEY)) == data
    assert aes_decrypt(cifrado, KEY) == data
