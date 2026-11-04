"""Contrato de la cascada AES-RC4 (``hybrid.py``).

El orden está fijado por el enunciado del trabajo: AES primero, RC4 después.
El descifrado invierte el orden. Estas pruebas fijan ese orden, los tamaños y
las invariantes que usa el equipo de Avalanche Effect.
"""

import pytest

from aes256 import aes_encrypt
from hybrid import generate_rc4_key, hybrid_decrypt, hybrid_encrypt
from integrity import bit_errors
from rc4 import rc4_encrypt

AES_KEY = bytes(range(32))
RC4_KEY = b"rc4-secreto-16b"


def padded_len(n: int) -> int:
    return 16 * (n // 16 + 1)


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 31, 32, 33, 1000])
def test_round_trip(n):
    data = bytes((i * 7) % 256 for i in range(n))
    ct = hybrid_encrypt(data, AES_KEY, RC4_KEY)
    assert hybrid_decrypt(ct, AES_KEY, RC4_KEY) == data


def test_round_trip_un_megabyte():
    data = bytes((i * 31) % 256 for i in range(1_000_000))
    ct = hybrid_encrypt(data, AES_KEY, RC4_KEY)
    assert hybrid_decrypt(ct, AES_KEY, RC4_KEY) == data


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 1000])
def test_tamano_es_el_de_aes(n):
    """RC4 no cambia longitudes: el híbrido mide lo mismo que AES."""
    data = bytes(n)
    assert len(hybrid_encrypt(data, AES_KEY, RC4_KEY)) == padded_len(n)


def test_orden_es_aes_luego_rc4():
    data = b"orden explicito de la cascada"
    assert hybrid_encrypt(data, AES_KEY, RC4_KEY) == rc4_encrypt(
        aes_encrypt(data, AES_KEY), RC4_KEY
    )


def test_no_es_ninguno_de_los_dos_cifradores_solo():
    data = b"no debe coincidir con AES ni con RC4 solos"
    ct = hybrid_encrypt(data, AES_KEY, RC4_KEY)
    assert ct != aes_encrypt(data, AES_KEY)
    assert ct != rc4_encrypt(data, RC4_KEY)


def test_es_determinista():
    data = b"misma entrada, misma salida"
    assert hybrid_encrypt(data, AES_KEY, RC4_KEY) == hybrid_encrypt(
        data, AES_KEY, RC4_KEY
    )


def test_acepta_bytes_like():
    data = bytearray(b"hola mundo")
    ct = hybrid_encrypt(memoryview(data), AES_KEY, RC4_KEY)
    assert hybrid_decrypt(ct, AES_KEY, RC4_KEY) == bytes(data)


# --- Invariantes para el equipo de Avalanche Effect -------------------------


def test_invertir_bit_de_clave_aes_conserva_la_distancia_de_hamming():
    """RC4 es XOR con un keystream: no altera dH si su clave no cambia.

    Consecuencia práctica: si la fila "AES-RC4" del informe se mide cambiando
    un bit de la clave AES, el resultado es *idéntico* al de AES. No es un bug.
    """
    data = b"El mismo mensaje para comparar invariantes. " * 4
    aes_key_2 = bytes([AES_KEY[0] ^ 0x01]) + AES_KEY[1:]

    aes_1 = aes_encrypt(data, AES_KEY)
    aes_2 = aes_encrypt(data, aes_key_2)
    hyb_1 = hybrid_encrypt(data, AES_KEY, RC4_KEY)
    hyb_2 = hybrid_encrypt(data, aes_key_2, RC4_KEY)

    assert bit_errors(hyb_1, hyb_2) == bit_errors(aes_1, aes_2)
    assert bit_errors(hyb_1, hyb_2) > 0


def test_invertir_bit_de_clave_rc4_cambia_el_criptograma():
    data = b"El mismo mensaje para comparar invariantes. " * 4
    rc4_key_2 = bytes([RC4_KEY[0] ^ 0x01]) + RC4_KEY[1:]

    hyb_1 = hybrid_encrypt(data, AES_KEY, RC4_KEY)
    hyb_2 = hybrid_encrypt(data, AES_KEY, rc4_key_2)

    assert hyb_1 != hyb_2
    assert bit_errors(hyb_1, hyb_2) > 0


# --- Contrato de errores ----------------------------------------------------


def test_rechaza_tipos_que_no_son_bytes():
    with pytest.raises(TypeError):
        hybrid_encrypt("texto", AES_KEY, RC4_KEY)
    with pytest.raises(TypeError):
        hybrid_encrypt(b"x", "k" * 32, RC4_KEY)
    with pytest.raises(TypeError):
        hybrid_encrypt(b"x", AES_KEY, "clave")
    # rc4.py convertiría un int con bytes(key); la frontera de hybrid lo corta.
    with pytest.raises(TypeError):
        hybrid_encrypt(b"x", AES_KEY, 32)


@pytest.mark.parametrize("bad_len", [0, 1, 16, 24, 31, 33, 64])
def test_rechaza_clave_aes_que_no_sea_de_32(bad_len):
    with pytest.raises(ValueError):
        hybrid_encrypt(b"x", b"k" * bad_len, RC4_KEY)
    with pytest.raises(ValueError):
        hybrid_decrypt(b"x" * 16, b"k" * bad_len, RC4_KEY)


@pytest.mark.parametrize("bad_len", [0, 257])
def test_rechaza_clave_rc4_fuera_de_rango(bad_len):
    with pytest.raises(ValueError):
        hybrid_encrypt(b"x", AES_KEY, b"k" * bad_len)
    with pytest.raises(ValueError):
        hybrid_decrypt(b"x" * 16, AES_KEY, b"k" * bad_len)


@pytest.mark.parametrize("bad_len", [1, 15, 17, 31])
def test_rechaza_criptograma_truncado(bad_len):
    with pytest.raises(ValueError):
        hybrid_decrypt(b"x" * bad_len, AES_KEY, RC4_KEY)


def test_clave_incorrecta_falla_al_quitar_el_padding():
    """La detección es probabilística (~255/256), pero este caso es estable."""
    msg = b"Informe AES-RC4: recuperacion exacta."
    ct = hybrid_encrypt(msg, AES_KEY, RC4_KEY)

    with pytest.raises(ValueError):
        hybrid_decrypt(ct, bytes(range(1, 33)), RC4_KEY)
    with pytest.raises(ValueError):
        hybrid_decrypt(ct, AES_KEY, b"rc4-secreto-16c")


def test_generate_rc4_key():
    for size in (1, 16, 32, 256):
        key = generate_rc4_key(size)
        assert isinstance(key, bytes)
        assert len(key) == size
    assert generate_rc4_key(16) != generate_rc4_key(16)
    with pytest.raises(ValueError):
        generate_rc4_key(0)
    with pytest.raises(ValueError):
        generate_rc4_key(257)
