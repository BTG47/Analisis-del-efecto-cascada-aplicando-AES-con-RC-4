"""Tests de la API pública con padding (la que usan José y Diego)."""

import pytest

from aes256 import aes_decrypt, aes_encrypt, generate_key

KEY = bytes(range(32))
WRONG_KEY = bytes(range(1, 33))


def padded_len(n: int) -> int:
    """Largo del criptograma AES-256-ECB con PKCS#7."""
    return 16 * (n // 16 + 1)


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 31, 32, 33, 1000, 1_000_000])
def test_round_trip(n):
    data = bytes((i * 7) % 256 for i in range(n))
    cifrado = aes_encrypt(data, KEY)
    assert len(cifrado) == padded_len(n)
    assert aes_decrypt(cifrado, KEY) == data


def test_es_determinista():
    """ECB sin IV: mismo texto y misma clave producen el mismo criptograma."""
    assert aes_encrypt(b"mismo texto", KEY) == aes_encrypt(b"mismo texto", KEY)


def test_textos_distintos_dan_criptogramas_distintos():
    assert aes_encrypt(b"texto A", KEY) != aes_encrypt(b"texto B", KEY)


@pytest.mark.parametrize("bad_len", [0, 1, 16, 24, 31, 33, 64])
def test_clave_debe_medir_32_bytes(bad_len):
    with pytest.raises(ValueError):
        aes_encrypt(b"x", b"k" * bad_len)
    with pytest.raises(ValueError):
        aes_decrypt(b"x" * 16, b"k" * bad_len)


def test_texto_no_es_bytes():
    with pytest.raises(TypeError):
        aes_encrypt("no soy bytes", KEY)
    with pytest.raises(TypeError):
        aes_encrypt(b"x", 1234)


def test_acepta_bytearray_y_devuelve_bytes():
    cifrado = aes_encrypt(bytearray(b"hola"), KEY)
    assert isinstance(cifrado, bytes)
    assert aes_decrypt(cifrado, KEY) == b"hola"


def test_clave_incorrecta_lanza_value_error():
    """Par determinista: con esta clave el relleno resultante es inválido."""
    cifrado = aes_encrypt(b"Informe AES-RC4: recuperacion exacta.", KEY)
    with pytest.raises(ValueError):
        aes_decrypt(cifrado, WRONG_KEY)


def test_criptograma_truncado_lanza_value_error():
    with pytest.raises(ValueError):
        aes_decrypt(b"no es multiplo", KEY)
    with pytest.raises(ValueError):
        aes_decrypt(b"", KEY)


def test_generate_key():
    k1 = generate_key()
    k2 = generate_key()
    assert isinstance(k1, bytes)
    assert len(k1) == 32
    assert k1 != k2
    # y sirve para cifrar
    assert aes_decrypt(aes_encrypt(b"x", k1), k1) == b"x"
