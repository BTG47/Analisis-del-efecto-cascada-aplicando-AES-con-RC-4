"""Tests de PKCS#7. No requieren criptografía: son aritmética de bytes."""

import pytest

from padding import BLOCK_SIZE, MAX_BLOCK_SIZE, pkcs7_pad, pkcs7_unpad


def test_block_size_es_16():
    assert BLOCK_SIZE == 16


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 31, 32, 33, 1000])
def test_round_trip(n):
    data = bytes((i * 7) % 256 for i in range(n))
    padded = pkcs7_pad(data)
    assert len(padded) % BLOCK_SIZE == 0
    assert len(padded) > len(data)  # siempre agrega al menos un byte
    assert pkcs7_unpad(padded) == data


def test_vacio_agrega_bloque_completo():
    assert pkcs7_pad(b"") == b"\x10" * 16


def test_multiplo_exacto_agrega_bloque_completo():
    padded = pkcs7_pad(b"A" * 16)
    assert len(padded) == 32
    assert padded[16:] == b"\x10" * 16


def test_quince_bytes_agrega_uno():
    padded = pkcs7_pad(b"A" * 15)
    assert len(padded) == 16
    assert padded[-1] == 0x01


def test_unpad_acepta_cola_valida():
    # 16 bytes: "ab" + 14 bytes de valor 14
    assert pkcs7_unpad(b"ab" + b"\x0e" * 14) == b"ab"
    # bloque entero de relleno: el mensaje original era vacío
    assert pkcs7_unpad(b"\x10" * 16) == b""


@pytest.mark.parametrize(
    "bad",
    [
        b"",  # vacío
        b"abc",  # longitud no múltiplo de 16
        b"A" * 15 + b"\x00",  # n = 0 (inválido)
        b"A" * 15 + b"\x11",  # 0x11 = 17 > block_size
        b"A" * 15 + b"\x02",  # la cola no repite el valor 2
        b"ab" + b"\x0c" * 12 + b"\x01\x02",  # último byte 2, cola 01 02
    ],
)
def test_unpad_rechaza_relleno_invalido(bad):
    with pytest.raises(ValueError):
        pkcs7_unpad(bad)


def test_rechaza_texto():
    with pytest.raises(TypeError):
        pkcs7_pad("no soy bytes")
    with pytest.raises(TypeError):
        pkcs7_unpad("no soy bytes")


def test_acepta_bytearray():
    assert pkcs7_unpad(pkcs7_pad(bytearray(b"hola"))) == b"hola"


def test_unpad_rechaza_block_size_cero():
    """Sin la validación, ``len(data) % 0`` lanzaría ZeroDivisionError."""
    with pytest.raises(ValueError):
        pkcs7_unpad(b"\x10" * 16, 0)


def test_unpad_rechaza_block_size_mayor_que_255():
    """PKCS#7 guarda el largo del relleno en un byte: 256 no es válido.

    Con datos alineados a ese tamaño, la versión sin validar devolvía bytes en
    silencio en lugar de rechazar el block_size.
    """
    with pytest.raises(ValueError):
        pkcs7_unpad(b"\x01" * 256, 256)


@pytest.mark.parametrize("modulo", [pkcs7_pad, pkcs7_unpad])
def test_block_size_debe_ser_entero(modulo):
    with pytest.raises(TypeError):
        modulo(b"\x10" * 16, "16")
