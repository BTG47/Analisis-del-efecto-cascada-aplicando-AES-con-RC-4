"""Contrato de ``integrity.py`` (módulo de José).

Se prueba lo que usa el equipo para el informe: distancia de Hamming, BER y el
registro de ``check_integrity``. ``ber`` también es la métrica del efecto
avalancha cuando se aplica a dos criptogramas.
"""

import hashlib

import pytest

from integrity import ber, bit_errors, check_integrity, identical, sha256_hex


@pytest.mark.parametrize(
    "a,b,esperado",
    [
        (b"", b"", 0),
        (b"\x00", b"\x00", 0),
        (b"\x00", b"\x01", 1),
        (b"\xff", b"\x00", 8),
        (b"\x00\x00", b"\xff\xff", 16),
        (b"", b"\x00", 8),  # el byte faltante cuenta como 8 errores
        (b"ab", b"abc", 8),
    ],
)
def test_bit_errors(a, b, esperado):
    assert bit_errors(a, b) == esperado


def test_bit_errors_es_simetrico():
    a, b = b"\x01\x02\x03", b"\x01\xff\x00"
    assert bit_errors(a, b) == bit_errors(b, a)


@pytest.mark.parametrize(
    "original,recuperado,esperado",
    [
        (b"", b"", 0.0),
        (b"abc", b"abc", 0.0),
        (b"\x00", b"\xff", 1.0),
        (b"", b"\x00", 1.0),
        (b"ab", b"abc", 8 / 24),
    ],
)
def test_ber(original, recuperado, esperado):
    assert ber(original, recuperado) == pytest.approx(esperado)


def test_ber_esta_acotado_entre_0_y_1():
    for n in (0, 1, 16, 100):
        original = bytes((i * 7) % 256 for i in range(n))
        recuperado = bytes((i * 11) % 256 for i in range(n))
        assert 0.0 <= ber(original, recuperado) <= 1.0


def test_sha256_y_identical():
    assert sha256_hex(b"") == hashlib.sha256(b"").hexdigest()
    assert sha256_hex(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert identical(b"abc", b"abc") is True
    assert identical(b"abc", b"abd") is False


def test_check_integrity_recuperacion_exacta():
    data = b"Informe AES-RC4: recuperacion exacta."
    report = check_integrity(data, data)
    assert report["original_size"] == len(data)
    assert report["decrypted_size"] == len(data)
    assert report["identical"] is True
    assert report["sha256_match"] is True
    assert report["bit_errors"] == 0
    assert report["ber"] == 0.0


def test_check_integrity_detecta_un_solo_bit():
    original = bytes(32)
    corrupto = b"\x01" + bytes(31)
    report = check_integrity(original, corrupto)
    assert report["identical"] is False
    assert report["sha256_match"] is False
    assert report["bit_errors"] == 1
    assert report["ber"] == pytest.approx(1 / 256)
