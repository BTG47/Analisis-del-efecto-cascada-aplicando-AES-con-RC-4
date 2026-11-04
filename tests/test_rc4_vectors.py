"""Compuerta de integración para ``rc4.py`` (módulo de José).

No modifica nada de su implementación: fija los vectores clásicos de RC4 para
detectar cualquier cambio que rompa el contrato compartido antes de componer la
cascada AES-RC4.
"""

import pytest

from rc4 import keystream, rc4_decrypt, rc4_encrypt

# key, plaintext, ciphertext esperado (vectores públicos de referencia)
VECTORES = [
    (b"Key", b"Plaintext", "bbf316e8d940af0ad3"),
    (b"Wiki", b"pedia", "1021bf0420"),
    (b"Secret", b"Attack at dawn", "45a01f645fc35b383552544b9bf5"),
]


@pytest.mark.parametrize("key,plain,esperado", VECTORES)
def test_vectores_clasicos(key, plain, esperado):
    assert rc4_encrypt(plain, key).hex() == esperado


@pytest.mark.parametrize("key,plain,esperado", VECTORES)
def test_vectores_clasicos_son_simetricos(key, plain, esperado):
    assert rc4_decrypt(bytes.fromhex(esperado), key) == plain


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 1000])
def test_longitud_preservada(n):
    """RC4 es un cifrador de flujo: sin padding, sin IV, sin cabecera."""
    data = bytes((i * 13) % 256 for i in range(n))
    assert len(rc4_encrypt(data, b"clave-de-prueba")) == n


@pytest.mark.parametrize("n", [0, 1, 16, 1000])
def test_round_trip(n):
    data = bytes((i * 29) % 256 for i in range(n))
    for key in (b"k", b"clave-de-16-bytes", bytes(range(32))):
        assert rc4_decrypt(rc4_encrypt(data, key), key) == data


def test_keystream_es_determinista_y_estable():
    assert keystream(b"Key", 16) == keystream(b"Key", 16)
    # Los primeros bytes del keystream son el cifrado de ceros.
    assert keystream(b"Key", 16) == rc4_encrypt(bytes(16), b"Key")
